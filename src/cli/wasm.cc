/*
 * Copyright (C) 2025 Dyne.org foundation
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
 * WASM-friendly wrapper functions for longfellow-zk
 * 
 * These functions accept only string arguments (no pointers) to make them
 * easy to call from WASM hosts like wasmtime, Node.js, browsers, etc.
 * 
 * All functions return:
 *   0 = success
 *   non-zero = error code
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "cli/json.hpp"
#include "circuits/mdoc/mdoc_zk.h"
#include "circuits/base64/decode_util.h"
#include "util/crypto.h"

using json = nlohmann::json;

// Simple encoding helpers for WASM (no exceptions)
namespace {
    // Base64 encoding table
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string bytes_to_base64(const uint8_t* data, size_t len) {
        std::string ret;
        int i = 0;
        uint8_t char_array_3[3];
        uint8_t char_array_4[4];
        
        while (len--) {
            char_array_3[i++] = *(data++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                
                for(i = 0; i < 4; i++)
                    ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }
        
        if (i) {
            for(int j = i; j < 3; j++)
                char_array_3[j] = '\0';
            
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            
            for (int j = 0; j < i + 1; j++)
                ret += base64_chars[char_array_4[j]];
            
            while(i++ < 3)
                ret += '=';
        }
        
        return ret;
    }
    
    std::vector<uint8_t> base64_to_bytes(const std::string& encoded) {
        std::vector<uint8_t> out;
        proofs::base64_decode_url(encoded, out);
        return out;
    }
    
    std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = (uint8_t) strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }
    
    std::string bytes_to_hex(const uint8_t* data, size_t len) {
        char* hex_str = (char*)malloc(len * 2 + 1);
        proofs::hex_to_str(hex_str, data, len);
        std::string result(hex_str);
        free(hex_str);
        return result;
    }
}

extern "C" {

/**
 * Generate a ZK circuit and print to stdout
 * 
 * @param zkspec_index Integer zkspec index (0-7)
 * @return 0 on success, error code otherwise
 * 
 * Example:
 *   wasm_generate_circuit(0)
 */
int wasm_generate_circuit(int zkspec_index) {
    fprintf(stderr, "[DEBUG] wasm_generate_circuit called with zkspec_index=%d\n", zkspec_index);
    
    if (zkspec_index < 0 || zkspec_index >= kNumZkSpecs) {
        fprintf(stderr, "Error: Invalid zkspec index %d (must be 0-%d)\n", 
                zkspec_index, kNumZkSpecs - 1);
        return 2;
    }

    const auto* zk_spec = &kZkSpecs[zkspec_index];
    fprintf(stderr, "Generating circuit for zkspec %d: %s v%zu (%zu attributes)\n",
           zkspec_index, zk_spec->system, zk_spec->version, zk_spec->num_attributes);

    // Generate circuit
    uint8_t* circuit_bytes = nullptr;
    size_t circuit_len = 0;
    
    auto result = generate_circuit(zk_spec, &circuit_bytes, &circuit_len);
    
    if (result != CIRCUIT_GENERATION_SUCCESS) {
        fprintf(stderr, "Circuit generation failed with error code: %d\n", result);
        return 10 + result;
    }

    if (!circuit_bytes || circuit_len == 0) {
        fprintf(stderr, "Circuit generation returned null or empty circuit\n");
        return 3;
    }

    fprintf(stderr, "Circuit generated: %zu bytes\n", circuit_len);

    // Create JSON output
    json output_json;
    output_json["circuit_data_base64"] = bytes_to_base64(circuit_bytes, circuit_len);
    output_json["_circuit_size"] = circuit_len;
    output_json["_zkspec"] = {
        {"index", zkspec_index},
        {"system", zk_spec->system},
        {"version", zk_spec->version},
        {"num_attributes", zk_spec->num_attributes},
        {"circuit_hash", zk_spec->circuit_hash}
    };

    // Print JSON to stdout
    printf("%s\n", output_json.dump(2).c_str());

    free(circuit_bytes);
    
    fprintf(stderr, "✓ Circuit generation complete\n");
    return 0;
}

/**
 * Generate a proof from mDoc JSON file
 * 
 * @param circuit_file Path to circuit JSON file
 * @param mdoc_file Path to mDoc JSON file (contains all parameters)
 * @param output_file Path to output proof JSON file
 * @return 0 on success, error code otherwise
 * 
 * The mdoc_file should contain:
 *   - mdoc_data_base64: Base64-encoded mDoc bytes
 *   - public_key: {x, y} issuer public key hex strings
 *   - transcript: Hex-encoded transcript
 *   - time: ISO 8601 timestamp
 *   - doc_type: Document type string
 *   - attributes: Array of requested attributes
 *   - zkspec: ZK spec index
 * 
 * Example:
 *   wasm_generate_proof("circuit.json", "mdoc.json", "proof.json")
 */
int wasm_generate_proof(const char* circuit_file, const char* mdoc_file, const char* output_file) {
    if (!circuit_file || !mdoc_file || !output_file) {
        fprintf(stderr, "Error: NULL arguments\n");
        return 1;
    }

    // Read circuit file
    std::ifstream circuit_in(circuit_file);
    if (!circuit_in) {
        fprintf(stderr, "Failed to open circuit file: %s\n", circuit_file);
        return 2;
    }
    json circuit_json;
    circuit_in >> circuit_json;
    circuit_in.close();

    auto circuit_data = base64_to_bytes(
        circuit_json["circuit_data_base64"].get<std::string>());

    // Read mDoc file
    std::ifstream mdoc_in(mdoc_file);
    if (!mdoc_in) {
        fprintf(stderr, "Failed to open mDoc file: %s\n", mdoc_file);
        return 3;
    }
    json mdoc_json;
    mdoc_in >> mdoc_json;
    mdoc_in.close();

    // Extract parameters from mDoc JSON
    auto mdoc_data = base64_to_bytes(
        mdoc_json["mdoc_data_base64"].get<std::string>());
    
    std::string pkx_hex = mdoc_json["public_key"]["x"].get<std::string>();
    std::string pky_hex = mdoc_json["public_key"]["y"].get<std::string>();
    std::string transcript_hex = mdoc_json["transcript"].get<std::string>();
    std::string time_str = mdoc_json["time"].get<std::string>();
    std::string doc_type = mdoc_json["doc_type"].get<std::string>();
    int zkspec_index = mdoc_json["zkspec"].get<int>();

    auto transcript_bytes = hex_to_bytes(transcript_hex);

    // Parse attributes
    std::vector<RequestedAttribute> attrs;
    if (mdoc_json.contains("attributes")) {
        for (const auto& attr_json : mdoc_json["attributes"]) {
            RequestedAttribute attr = {};
            std::string ns = attr_json["namespace"];
            std::string id = attr_json["id"];
            std::string cbor_hex = attr_json["cbor_value"];
            auto cbor_bytes = hex_to_bytes(cbor_hex);

            std::memcpy(attr.namespace_id, ns.c_str(), 
                       std::min(ns.size(), sizeof(attr.namespace_id)));
            std::memcpy(attr.id, id.c_str(), 
                       std::min(id.size(), sizeof(attr.id)));
            std::memcpy(attr.cbor_value, cbor_bytes.data(), 
                       std::min(cbor_bytes.size(), sizeof(attr.cbor_value)));
            attr.namespace_len = std::min(ns.size(), sizeof(attr.namespace_id));
            attr.id_len = std::min(id.size(), sizeof(attr.id));
            attr.cbor_value_len = std::min(cbor_bytes.size(), sizeof(attr.cbor_value));

            attrs.push_back(attr);
        }
    }

    // Handle empty attributes case
    RequestedAttribute dummy_attr = {};
    const RequestedAttribute* attrs_ptr = attrs.empty() ? &dummy_attr : attrs.data();
    size_t attrs_len = attrs.size();

    const auto* zk_spec = &kZkSpecs[zkspec_index];

    printf("Generating proof for %zu attributes...\n", attrs_len);

    // Generate proof
    uint8_t* proof = nullptr;
    size_t proof_len = 0;
    
    auto result = run_mdoc_prover(
        circuit_data.data(), circuit_data.size(),
        mdoc_data.data(), mdoc_data.size(),
        pkx_hex.c_str(), pky_hex.c_str(),
        transcript_bytes.data(), transcript_bytes.size(),
        attrs_ptr, attrs_len,
        time_str.c_str(),
        &proof, &proof_len, zk_spec
    );

    if (result != MDOC_PROVER_SUCCESS) {
        fprintf(stderr, "Proof generation failed with error code: %d\n", result);
        return 10 + result;
    }

    // Create output JSON
    json output_json;
    output_json["proof_data_base64"] = bytes_to_base64(proof, proof_len);
    output_json["public_key"] = mdoc_json["public_key"];
    output_json["transcript"] = transcript_hex;
    output_json["time"] = time_str;
    output_json["doc_type"] = doc_type;
    output_json["attributes"] = mdoc_json["attributes"];
    output_json["zkspec"] = zkspec_index;

    // Write to file
    std::ofstream out(output_file);
    if (!out) {
        fprintf(stderr, "Failed to open output file: %s\n", output_file);
        free(proof);
        return 4;
    }

    out << output_json.dump(2);
    out.close();

    free(proof);
    
    printf("✓ Proof saved to: %s (%zu bytes)\n", output_file, proof_len);
    return 0;
}

/**
 * Verify a proof from JSON files
 * 
 * @param circuit_file Path to circuit JSON file
 * @param proof_file Path to proof JSON file (contains all verification parameters)
 * @return 0 on success, error code otherwise
 * 
 * Example:
 *   wasm_verify_proof("circuit.json", "proof.json")
 */
int wasm_verify_proof(const char* circuit_file, const char* proof_file) {
    if (!circuit_file || !proof_file) {
        fprintf(stderr, "Error: NULL arguments\n");
        return 1;
    }

    // Read circuit file
    std::ifstream circuit_in(circuit_file);
    if (!circuit_in) {
        fprintf(stderr, "Failed to open circuit file: %s\n", circuit_file);
        return 2;
    }
    json circuit_json;
    circuit_in >> circuit_json;
    circuit_in.close();

    auto circuit_data = base64_to_bytes(
        circuit_json["circuit_data_base64"].get<std::string>());

    // Read proof file
    std::ifstream proof_in(proof_file);
    if (!proof_in) {
        fprintf(stderr, "Failed to open proof file: %s\n", proof_file);
        return 3;
    }
    json proof_json;
    proof_in >> proof_json;
    proof_in.close();

    // Extract parameters
    auto proof_data = base64_to_bytes(
        proof_json["proof_data_base64"].get<std::string>());
    
    std::string pkx_hex = proof_json["public_key"]["x"].get<std::string>();
    std::string pky_hex = proof_json["public_key"]["y"].get<std::string>();
    std::string transcript_hex = proof_json["transcript"].get<std::string>();
    std::string time_str = proof_json["time"].get<std::string>();
    std::string doc_type = proof_json["doc_type"].get<std::string>();
    int zkspec_index = proof_json["zkspec"].get<int>();

    auto transcript_bytes = hex_to_bytes(transcript_hex);

    // Parse attributes
    std::vector<RequestedAttribute> attrs;
    if (proof_json.contains("attributes")) {
        for (const auto& attr_json : proof_json["attributes"]) {
            RequestedAttribute attr = {};
            std::string ns = attr_json["namespace"];
            std::string id = attr_json["id"];
            std::string cbor_hex = attr_json["cbor_value"];
            auto cbor_bytes = hex_to_bytes(cbor_hex);

            std::memcpy(attr.namespace_id, ns.c_str(), 
                       std::min(ns.size(), sizeof(attr.namespace_id)));
            std::memcpy(attr.id, id.c_str(), 
                       std::min(id.size(), sizeof(attr.id)));
            std::memcpy(attr.cbor_value, cbor_bytes.data(), 
                       std::min(cbor_bytes.size(), sizeof(attr.cbor_value)));
            attr.namespace_len = std::min(ns.size(), sizeof(attr.namespace_id));
            attr.id_len = std::min(id.size(), sizeof(attr.id));
            attr.cbor_value_len = std::min(cbor_bytes.size(), sizeof(attr.cbor_value));

            attrs.push_back(attr);
        }
    }

    // Handle empty attributes case
    RequestedAttribute dummy_attr = {};
    const RequestedAttribute* attrs_ptr = attrs.empty() ? &dummy_attr : attrs.data();
    size_t attrs_len = attrs.size();

    const auto* zk_spec = &kZkSpecs[zkspec_index];

    printf("Verifying proof with %zu attributes...\n", attrs_len);

    // Verify proof
    auto result = run_mdoc_verifier(
        circuit_data.data(), circuit_data.size(),
        pkx_hex.c_str(), pky_hex.c_str(),
        transcript_bytes.data(), transcript_bytes.size(),
        attrs_ptr, attrs_len,
        time_str.c_str(),
        proof_data.data(), proof_data.size(),
        doc_type.c_str(),
        zk_spec
    );

    if (result != MDOC_VERIFIER_SUCCESS) {
        fprintf(stderr, "✗ Verification failed with error code: %d\n", result);
        return 10 + result;
    }

    printf("✓ Proof verification successful!\n");
    return 0;
}

} // extern "C"
