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
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "cli/json.hpp"
#include "circuits/bip340/bip340_guard.h"
#include "circuits/bip340/bip340_verify.h"
#include "circuits/bip340/bip340_witness.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "circuits/tests/base64/decode_util.h"
#include "ec/p256k1.h"
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/crypto.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

enum : size_t {
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

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        int hi = hex_value(hex[i]);
        int lo = hex_value(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
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

static long elapsed_ms(Clock::time_point start, Clock::time_point finish) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(finish - start).count();
}

static int run_bip340_smoke(json &output, char *err_buf, size_t err_len) {
    constexpr size_t kRate = 4;
    constexpr size_t kQueries = 128;
    using Field = proofs::Fp256k1Base;
    using EC = proofs::P256k1;
    using Backend = proofs::CompilerBackend<Field>;
    using LogicCircuit = proofs::Logic<Field, Backend>;
    using Verify = proofs::Bip340Verify<LogicCircuit, Field, EC>;
    using Crt = proofs::CRT256<Field>;
    using ConvolutionFactory = proofs::CrtConvolutionFactory<Crt, Field>;
    using RSFactory = proofs::ReedSolomonFactory<Field, ConvolutionFactory>;

    json steps = json::array();
    auto phase_start = Clock::now();

    proofs::QuadCircuit<Field> q(proofs::p256k1_base);
    std::unique_ptr<proofs::Circuit<Field>> circuit;
    {
        const Backend backend(&q);
        const LogicCircuit logic(&backend, proofs::p256k1_base);
        Verify verify(logic, proofs::p256k1);

        auto rx_wire = logic.eltw_input();
        auto px_wire = logic.eltw_input();
        auto e_wire = logic.eltw_input();

        typename Verify::Witness circuit_witness;
        q.private_input();
        circuit_witness.input(logic);
        verify.assert_verify(rx_wire, px_wire, e_wire, circuit_witness);

        circuit = q.mkcircuit(1);
    }
    if (!circuit) {
        return buf_err(err_buf, err_len, "BIP340 circuit build returned null");
    }
    if (circuit->npub_in == 0 || circuit->ninputs <= circuit->npub_in) {
        return buf_err(err_buf, err_len,
                       "BIP340 circuit has invalid input shape: public=%zu total=%zu",
                       circuit->npub_in, circuit->ninputs);
    }

    size_t block_enc = circuit->ninputs - circuit->npub_in + q.nquad_terms_ + 1;
    auto err = proofs::check_crt_block_enc<Crt>(block_enc);
    if (!err.empty()) {
        return buf_err(err_buf, err_len, "%s", err.c_str());
    }

    std::vector<uint8_t> circuit_bytes;
    proofs::CircuitWriter<Field> writer(proofs::p256k1_base, proofs::SECP_ID);
    writer.to_bytes(*circuit, circuit_bytes);

    proofs::ReadBuffer rb(circuit_bytes.data(), circuit_bytes.size());
    proofs::CircuitReader<Field> reader(proofs::p256k1_base, proofs::SECP_ID);
    auto decoded = reader.from_bytes(rb, true);
    if (!decoded) {
        return buf_err(err_buf, err_len,
                       "BIP340 serialized circuit failed round-trip decode");
    }
    auto phase_finish = Clock::now();
    steps.push_back({{"phase", "build_serialize_circuit"},
                     {"ms", elapsed_ms(phase_start, phase_finish)},
                     {"compressed_bytes", circuit_bytes.size()}});

    auto pub = std::make_unique<proofs::Dense<Field>>(1, decoded->npub_in);
    auto witness_values = std::make_unique<proofs::Dense<Field>>(1, decoded->ninputs);

    auto pk = hex_to_bytes(
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    auto msg = hex_to_bytes(
        "0000000000000000000000000000000000000000000000000000000000000000");
    auto sig = hex_to_bytes(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
    if (pk.size() != 32 || msg.size() != 32 || sig.size() != 64) {
        return buf_err(err_buf, err_len, "BIP340 integration fixture malformed");
    }

    phase_start = Clock::now();
    proofs::Bip340Witness bip340_witness(proofs::p256k1);
    if (!bip340_witness.compute(sig.data(), pk.data(), msg.data(), msg.size())) {
        return buf_err(err_buf, err_len, "BIP340 fixture witness generation failed");
    }

    auto rx = proofs::p256k1_base.to_montgomery(
        proofs::Bip340Witness::nat_from_be_bytes(sig.data()));
    auto px = proofs::p256k1_base.to_montgomery(
        proofs::Bip340Witness::nat_from_be_bytes(pk.data()));

    {
        proofs::DenseFiller<Field> filler(*witness_values);
        filler.push_back(proofs::p256k1_base.one());
        filler.push_back(rx);
        filler.push_back(px);
        filler.push_back(bip340_witness.e_);
        bip340_witness.fill_witness(filler);
    }
    {
        proofs::DenseFiller<Field> filler(*pub);
        filler.push_back(proofs::p256k1_base.one());
        filler.push_back(rx);
        filler.push_back(px);
        filler.push_back(bip340_witness.e_);
    }

    {
        using EvalBackend = proofs::EvaluationBackend<Field>;
        using EvalLogic = proofs::Logic<Field, EvalBackend>;
        using EvalVerify = proofs::Bip340Verify<EvalLogic, Field, EC>;

        const EvalBackend eval_backend(proofs::p256k1_base, false);
        const EvalLogic eval_logic(&eval_backend, proofs::p256k1_base);
        EvalVerify eval_verify(eval_logic, proofs::p256k1);

        typename EvalVerify::Witness eval_witness;
        for (size_t i = 0; i < proofs::Bip340Witness::kBits; ++i) {
            eval_witness.bits_s[i] = eval_logic.konst(bip340_witness.bits_s_[i]);
            eval_witness.bits_e[i] = eval_logic.konst(bip340_witness.bits_e_[i]);
            eval_witness.bits_ry[i] = eval_logic.konst(bip340_witness.bits_ry_[i]);
            if (i < proofs::Bip340Witness::kBits - 1) {
                eval_witness.int_sx[i] = eval_logic.konst(bip340_witness.int_sx_[i]);
                eval_witness.int_sy[i] = eval_logic.konst(bip340_witness.int_sy_[i]);
                eval_witness.int_sz[i] = eval_logic.konst(bip340_witness.int_sz_[i]);
                eval_witness.int_ex[i] = eval_logic.konst(bip340_witness.int_ex_[i]);
                eval_witness.int_ey[i] = eval_logic.konst(bip340_witness.int_ey_[i]);
                eval_witness.int_ez[i] = eval_logic.konst(bip340_witness.int_ez_[i]);
            }
        }
        eval_witness.py = eval_logic.konst(bip340_witness.py_);
        eval_witness.ry = eval_logic.konst(bip340_witness.ry_);
        eval_witness.rz_inv = eval_logic.konst(bip340_witness.rz_inv_);

        eval_verify.assert_verify(eval_logic.konst(rx),
                                  eval_logic.konst(px),
                                  eval_logic.konst(bip340_witness.e_),
                                  eval_witness);
        if (eval_backend.assertion_failed()) {
            return buf_err(err_buf, err_len,
                           "BIP340 fixture witness failed direct evaluation");
        }
    }

    ConvolutionFactory factory(proofs::p256k1_base);
    RSFactory rsf(factory, proofs::p256k1_base);
    proofs::SecureRandomEngine rng;

    uint8_t transcript_label[] = "bip340 wasm proof";
    proofs::Transcript tp(transcript_label, sizeof(transcript_label) - 1);

    proofs::ZkProof<Field> proof(*decoded, kRate, kQueries, block_enc);
    proofs::ZkProver<Field, RSFactory> prover(*decoded, proofs::p256k1_base, rsf);
    prover.commit(proof, *witness_values, tp, rng);
    if (!prover.prove(proof, *witness_values, tp)) {
        return buf_err(err_buf, err_len, "BIP340 proof generation failed");
    }

    std::vector<uint8_t> proof_bytes;
    proof.write(proof_bytes, proofs::p256k1_base);
    phase_finish = Clock::now();
    steps.push_back({{"phase", "witness_prove_serialize"},
                     {"ms", elapsed_ms(phase_start, phase_finish)},
                     {"compressed_bytes", proof_bytes.size()}});

    phase_start = Clock::now();
    proofs::ReadBuffer proof_rb(proof_bytes.data(), proof_bytes.size());
    proofs::ZkProof<Field> parsed_proof(*decoded, kRate, kQueries, block_enc);
    if (!parsed_proof.read(proof_rb, proofs::p256k1_base)) {
        return buf_err(err_buf, err_len, "BIP340 serialized proof failed decode");
    }

    proofs::Transcript tv(transcript_label, sizeof(transcript_label) - 1);
    proofs::ZkVerifier<Field, RSFactory> verifier(*decoded, rsf, kRate, kQueries,
                                                  block_enc, proofs::p256k1_base);
    verifier.recv_commitment(parsed_proof, tv);
    if (!verifier.verify(parsed_proof, *pub, tv)) {
        return buf_err(err_buf, err_len, "BIP340 verifier rejected proof");
    }
    phase_finish = Clock::now();
    steps.push_back({{"phase", "deserialize_verify_proof"},
                     {"ms", elapsed_ms(phase_start, phase_finish)},
                     {"compressed_bytes", proof_bytes.size()}});

    output["result"] = "bip340 smoke successful";
    output["steps"] = steps;
    output["circuit_data_hex"] = bytes_to_hex(circuit_bytes.data(), circuit_bytes.size());
    output["proof_data_hex"] = bytes_to_hex(proof_bytes.data(), proof_bytes.size());
    output["_circuit_size"] = circuit_bytes.size();
    output["_proof_size"] = proof_bytes.size();
    output["public_inputs"] = circuit->npub_in;
    output["total_inputs"] = circuit->ninputs;
    output["quad_terms"] = q.nquad_terms_;
    output["crt_block_enc"] = block_enc;
    return 0;
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
    if (!j.is_array()) {
        buf_err(err_buf, err_len, "attrs_json must be an array");
        return false;
    }
    for (const auto &a : j) {
        if (!a.is_object() ||
            !a.contains("namespace") || !a["namespace"].is_string() ||
            !a.contains("id") || !a["id"].is_string() ||
            !a.contains("cbor_value") || !a["cbor_value"].is_string()) {
            buf_err(err_buf, err_len,
                    "attrs_json entries must include string namespace, id, and cbor_value");
            return false;
        }

        RequestedAttribute attr = {};
        auto ns = a["namespace"].get<std::string>();
        auto id = a["id"].get<std::string>();
        auto cbor_hex = a["cbor_value"].get<std::string>();
        if (!is_hex(cbor_hex.c_str())) {
            buf_err(err_buf, err_len, "attrs_json cbor_value must be valid hex");
            return false;
        }
        if (ns.size() > sizeof(attr.namespace_id) ||
            id.size() > sizeof(attr.id) ||
            cbor_hex.size() / 2 > sizeof(attr.cbor_value)) {
            buf_err(err_buf, err_len, "attrs_json entry exceeds RequestedAttribute capacity");
            return false;
        }
        auto cbor_bytes = hex_to_bytes(cbor_hex);

        memcpy(attr.namespace_id, ns.c_str(), ns.size());
        memcpy(attr.id, id.c_str(), id.size());
        memcpy(attr.cbor_value, cbor_bytes.data(), cbor_bytes.size());
        attr.namespace_len = ns.size();
        attr.id_len = id.size();
        attr.cbor_value_len = cbor_bytes.size();
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
        auto a = json::parse(attrs_json, nullptr, false);
        if (!a.is_discarded()) output["attributes"] = a;
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

int longfellow_zk_bip340_smoke_tobuf(
    char *out_buf, size_t out_len,
    char *err_buf, size_t err_len) {

    buf_ok(out_buf, out_len);

    json output;
    int rc = run_bip340_smoke(output, err_buf, err_len);
    if (rc != 0) return rc;

    return buf_copy_or_err(out_buf, out_len, err_buf, err_len, output.dump());
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
