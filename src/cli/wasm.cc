/*
 * Copyright (C) 2025-2026 Dyne.org foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * WASM API for longfellow-zk — zenroom-style tobuf pattern.
 *
 * All binary inputs and outputs use lowercase hex strings.
 * Each function has a _tobuf variant that writes results to
 * pre-allocated buffers (out_buf / err_buf) instead of stdout/stderr.
 *
 * Return value: 0 = success, non-zero = error.
 */

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "cli/json.hpp"
#include "circuits/mdoc/mdoc_zk.h"
#include "circuits/tests/base64/decode_util.h"
#include "util/crypto.h"

using json = nlohmann::json;

enum : size_t {
    kDefaultOutLen = 65536,
    kCircuitOutLen = 8388608,
};

// -- buffer helpers ----------------------------------------------------

static int buf_ok(char *buf, size_t buf_len) {
    if (buf && buf_len > 0) buf[0] = '\0';
    return 0;
}

static int buf_err(char *buf, size_t buf_len, const char *fmt, ...) {
    if (buf && buf_len > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, buf_len, fmt, ap);
        va_end(ap);
    }
    return 1;
}

// -- hex <-> bytes -----------------------------------------------------

static std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        char byte_str[3] = {hex[i], hex[i + 1], '\0'};
        bytes.push_back(static_cast<uint8_t>(strtol(byte_str, nullptr, 16)));
    }
    return bytes;
}

static bool is_hex(const char *s) {
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++) {
        if (!((*p >= '0' && *p <= '9') ||
              (*p >= 'a' && *p <= 'f') ||
              (*p >= 'A' && *p <= 'F')))
            return false;
    }
    return (strlen(s) % 2) == 0;
}

static std::string bytes_to_hex(const uint8_t *data, size_t len) {
    char *hex_str = static_cast<char *>(malloc(len * 2 + 1));
    if (!hex_str) return "";
    proofs::hex_to_str(hex_str, data, len);
    std::string result(hex_str);
    free(hex_str);
    return result;
}

static bool buf_copy(char *dst, size_t dst_len, const std::string &src) {
    if (!dst || dst_len == 0) return false;
    if (src.size() >= dst_len) {
        dst[0] = '\0';
        return false;
    }
    memcpy(dst, src.c_str(), src.size() + 1);
    return true;
}

static int buf_copy_or_err(char *dst, size_t dst_len,
                           char *err_buf, size_t err_len,
                           const std::string &src) {
    if (buf_copy(dst, dst_len, src)) return 0;
    return buf_err(err_buf, err_len,
                   "output buffer too small: need %zu bytes, got %zu",
                   src.size() + 1, dst_len);
}

// -- attribute parsing ------------------------------------------------

static bool parse_attrs_json(const char *attrs_json,
                             std::vector<RequestedAttribute> &attrs,
                             char *err_buf, size_t err_len) {
    if (!attrs_json || !attrs_json[0]) return true; // no attrs is fine
    auto j = json::parse(attrs_json, nullptr, false);
    if (j.is_discarded()) {
        buf_err(err_buf, err_len, "failed to parse attrs_json");
        return false;
    }
    for (const auto &a : j) {
        RequestedAttribute attr = {};
        auto ns = a.value("namespace", "");
        auto id = a.value("id", "");
        auto cbor_hex = a.value("cbor_value", "");
        auto cbor_bytes = hex_to_bytes(cbor_hex);

        memcpy(attr.namespace_id, ns.c_str(),
               std::min(ns.size(), sizeof(attr.namespace_id)));
        memcpy(attr.id, id.c_str(),
               std::min(id.size(), sizeof(attr.id)));
        memcpy(attr.cbor_value, cbor_bytes.data(),
               std::min(cbor_bytes.size(), sizeof(attr.cbor_value)));
        attr.namespace_len = std::min(ns.size(), sizeof(attr.namespace_id));
        attr.id_len = std::min(id.size(), sizeof(attr.id));
        attr.cbor_value_len = std::min(cbor_bytes.size(), sizeof(attr.cbor_value));
        attrs.push_back(attr);
    }
    return true;
}

// -- public API (_tobuf variants) --------------------------------------

extern "C" {

int longfellow_zk_generate_circuit_tobuf(
    int zkspec_index,
    char *out_buf, size_t out_len,
    char *err_buf, size_t err_len) {

    if (zkspec_index < 0 || zkspec_index >= kNumZkSpecs) {
        return buf_err(err_buf, err_len,
                       "invalid zkspec index %d (must be 0-%d)",
                       zkspec_index, kNumZkSpecs - 1);
    }

    const auto *zk_spec = &kZkSpecs[zkspec_index];
    buf_ok(out_buf, out_len);

    uint8_t *circuit_bytes = nullptr;
    size_t circuit_len = 0;

    auto result = generate_circuit(zk_spec, &circuit_bytes, &circuit_len);
    if (result != CIRCUIT_GENERATION_SUCCESS) {
        free(circuit_bytes);
        return buf_err(err_buf, err_len,
                       "circuit generation failed: error %d", result);
    }

    if (!circuit_bytes || circuit_len == 0) {
        free(circuit_bytes);
        return buf_err(err_buf, err_len,
                       "circuit generation returned empty circuit");
    }

    std::string circuit_hex = bytes_to_hex(circuit_bytes, circuit_len);
    free(circuit_bytes);

    json output;
    output["circuit_data_hex"] = circuit_hex;
    output["_circuit_size"] = circuit_len;
    output["_zkspec"] = {
        {"index", zkspec_index},
        {"system", zk_spec->system},
        {"version", zk_spec->version},
        {"num_attributes", zk_spec->num_attributes},
        {"circuit_hash", zk_spec->circuit_hash}
    };

    return buf_copy_or_err(out_buf, out_len, err_buf, err_len, output.dump());
}

int longfellow_zk_generate_proof_tobuf(
    const char *circuit_hex,
    const char *mdoc_hex,
    const char *pkx_hex,
    const char *pky_hex,
    const char *transcript_hex,
    const char *time_str,
    const char *doc_type,
    int zkspec_index,
    const char *attrs_json,
    char *out_buf, size_t out_len,
    char *err_buf, size_t err_len) {

    // Validate required args
    if (!circuit_hex || !mdoc_hex || !pkx_hex || !pky_hex ||
        !transcript_hex || !time_str || !doc_type) {
        return buf_err(err_buf, err_len, "missing required argument");
    }

    if (!is_hex(circuit_hex)) return buf_err(err_buf, err_len, "circuit_hex: not valid hex");
    if (!is_hex(mdoc_hex)) return buf_err(err_buf, err_len, "mdoc_hex: not valid hex");
    if (!is_hex(transcript_hex)) return buf_err(err_buf, err_len, "transcript_hex: not valid hex");

    if (zkspec_index < 0 || zkspec_index >= kNumZkSpecs) {
        return buf_err(err_buf, err_len,
                       "invalid zkspec index %d", zkspec_index);
    }

    buf_ok(out_buf, out_len);

    auto circuit_data = hex_to_bytes(circuit_hex);
    auto mdoc_data = hex_to_bytes(mdoc_hex);
    auto transcript_bytes = hex_to_bytes(transcript_hex);

    // Parse attributes
    std::vector<RequestedAttribute> attrs;
    if (!parse_attrs_json(attrs_json, attrs, err_buf, err_len)) return 1;

    RequestedAttribute dummy_attr = {};
    const RequestedAttribute *attrs_ptr = attrs.empty() ? &dummy_attr : attrs.data();
    size_t attrs_len = attrs.size();

    const auto *zk_spec = &kZkSpecs[zkspec_index];

    uint8_t *proof = nullptr;
    size_t proof_len = 0;

    auto result = run_mdoc_prover(
        circuit_data.data(), circuit_data.size(),
        mdoc_data.data(), mdoc_data.size(),
        pkx_hex, pky_hex,
        transcript_bytes.data(), transcript_bytes.size(),
        attrs_ptr, attrs_len,
        time_str,
        &proof, &proof_len, zk_spec);

    if (result != MDOC_PROVER_SUCCESS) {
        free(proof);
        return buf_err(err_buf, err_len,
                       "proof generation failed: error %d", result);
    }

    // Re-parse attrs_json for JSON output (preserves original form)
    json output;
    output["proof_data_hex"] = bytes_to_hex(proof, proof_len);
    output["public_key"] = {{"x", pkx_hex}, {"y", pky_hex}};
    output["transcript"] = transcript_hex;
    output["time"] = time_str;
    output["doc_type"] = doc_type;
    output["zkspec"] = zkspec_index;
    if (attrs_json && attrs_json[0]) {
        if (attrs_json && attrs_json[0]) {
            auto a = json::parse(attrs_json, nullptr, false);
            if (!a.is_discarded()) output["attributes"] = a;
        }
    }

    free(proof);

    return buf_copy_or_err(out_buf, out_len, err_buf, err_len, output.dump());
}

int longfellow_zk_verify_proof_tobuf(
    const char *circuit_hex,
    const char *proof_hex,
    const char *pkx_hex,
    const char *pky_hex,
    const char *transcript_hex,
    const char *time_str,
    const char *doc_type,
    int zkspec_index,
    const char *attrs_json,
    char *out_buf, size_t out_len,
    char *err_buf, size_t err_len) {

    // Validate required args
    if (!circuit_hex || !proof_hex || !pkx_hex || !pky_hex ||
        !transcript_hex || !time_str || !doc_type) {
        return buf_err(err_buf, err_len, "missing required argument");
    }

    if (!is_hex(circuit_hex)) return buf_err(err_buf, err_len, "circuit_hex: not valid hex");
    if (!is_hex(proof_hex)) return buf_err(err_buf, err_len, "proof_hex: not valid hex");
    if (!is_hex(transcript_hex)) return buf_err(err_buf, err_len, "transcript_hex: not valid hex");

    if (zkspec_index < 0 || zkspec_index >= kNumZkSpecs) {
        return buf_err(err_buf, err_len,
                       "invalid zkspec index %d", zkspec_index);
    }

    buf_ok(out_buf, out_len);

    auto circuit_data = hex_to_bytes(circuit_hex);
    auto proof_data = hex_to_bytes(proof_hex);
    auto transcript_bytes = hex_to_bytes(transcript_hex);

    // Parse attributes
    std::vector<RequestedAttribute> attrs;
    if (!parse_attrs_json(attrs_json, attrs, err_buf, err_len)) return 1;

    RequestedAttribute dummy_attr = {};
    const RequestedAttribute *attrs_ptr = attrs.empty() ? &dummy_attr : attrs.data();
    size_t attrs_len = attrs.size();

    const auto *zk_spec = &kZkSpecs[zkspec_index];

    auto result = run_mdoc_verifier(
        circuit_data.data(), circuit_data.size(),
        pkx_hex, pky_hex,
        transcript_bytes.data(), transcript_bytes.size(),
        attrs_ptr, attrs_len,
        time_str,
        proof_data.data(), proof_data.size(),
        doc_type,
        zk_spec);

    if (result != MDOC_VERIFIER_SUCCESS) {
        return buf_err(err_buf, err_len,
                       "verification failed: error %d", result);
    }

    return buf_copy_or_err(out_buf, out_len, err_buf, err_len,
                           "{\"result\":\"verification successful\"}");
}

// -- compatibility wrappers (print to stdout) --------------------------
// These match the original wasm_* API, now implemented via _tobuf.

int wasm_generate_circuit(int zkspec_index) {
    char *out = static_cast<char *>(malloc(kCircuitOutLen));
    char err[2048] = {};
    if (!out) {
        fprintf(stderr, "wasm_generate_circuit: failed to allocate output buffer\n");
        return 1;
    }
    int rc = longfellow_zk_generate_circuit_tobuf(
        zkspec_index, out, kCircuitOutLen, err, sizeof(err));
    if (rc == 0) fprintf(stdout, "%s\n", out);
    else if (err[0]) fprintf(stderr, "%s\n", err);
    free(out);
    return rc;
}

int wasm_generate_proof(const char *circuit_file, const char *mdoc_file,
                        const char *output_file) {
    (void)circuit_file; (void)mdoc_file; (void)output_file;
    fprintf(stderr, "wasm_generate_proof: use longfellow_zk_generate_proof_tobuf instead\n");
    return 1;
}

int wasm_verify_proof(const char *circuit_file, const char *proof_file) {
    (void)circuit_file; (void)proof_file;
    fprintf(stderr, "wasm_verify_proof: use longfellow_zk_verify_proof_tobuf instead\n");
    return 1;
}

}  // extern "C"
