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

#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string_view>
#include <memory>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

#include "CLI11.hpp"
#include "json.hpp"
#include "encoding.h"
#include <magic_enum.hpp>
#include <circuits/mdoc/mdoc_zk.h>
#include <circuits/mdoc/mdoc_examples.h>

using json = nlohmann::json;

namespace fs = std::filesystem;

// Modern C++17 compatible string formatting
template<typename... Args>
std::string format_string(const std::string& format, Args... args) {
    int size_s = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    if (size_s <= 0) { throw std::runtime_error("Error during formatting."); }
    auto size = static_cast<size_t>(size_s);
    std::unique_ptr<char[]> buf(new char[size]);
    std::snprintf(buf.get(), size, format.c_str(), args...);
    return std::string(buf.get(), buf.get() + size - 1);
}

namespace fs = std::filesystem;

// Modern C++17 utility for file validation
constexpr auto validate_file = [](const std::string& filename) -> std::string {
    if (!fs::exists(filename)) {
        throw CLI::ValidationError("File '" + filename + "' does not exist");
    }
    if (!fs::is_regular_file(filename)) {
        throw CLI::ValidationError("'" + filename + "' is not a regular file");
    }
    return filename;
};

// RAII wrapper for reading files
class FileReader {
public:
    explicit FileReader(const std::string& filename) : filename_(filename) {
        std::ifstream file(filename_, std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("Cannot open file '" + filename_ + "'");
        }
        size_ = file.tellg();
        data_ = std::make_unique<uint8_t[]>(size_);
        file.seekg(0);
        file.read(reinterpret_cast<char*>(data_.get()), size_);
    }

    [[nodiscard]] const uint8_t* data() const noexcept { return data_.get(); }
    [[nodiscard]] size_t size() const noexcept { return size_; }
    [[nodiscard]] const std::string& filename() const noexcept { return filename_; }

private:
    std::string filename_;
    std::unique_ptr<uint8_t[]> data_;
    size_t size_;
};

// Command implementations using modern C++20 features
namespace commands {

// Helper function to list all available ZK specs
void list_zkspecs() {
    std::cout << "\nAvailable ZK specifications:\n";
    std::cout << "============================\n";
    for (int i = 0; i < kNumZkSpecs; i++) {
        const auto& spec = kZkSpecs[i];
        std::cout << format_string("  [%d] %s v%zu (%zu attributes)\n",
                                 i, spec.system, spec.version, spec.num_attributes);
        std::cout << format_string("      Hash: %s\n", spec.circuit_hash);
        std::cout << "\n";
    }
    std::cout << "Usage examples:\n";
    std::cout << "  --zkspec 0         # Use first spec\n";
    std::cout << "  --zkspec latest    # Use latest spec (default)\n";
    std::cout << "  --zkspec list      # Show this list\n";
}

// Helper function to find ZK spec by index or name
const ZkSpecStruct* find_zkspec(const std::string& spec_str) {
    if (spec_str == "list") {
        list_zkspecs();
        return nullptr;
    }

    if (spec_str == "latest") {
        // Find the spec with the highest version number (most recent)
        const ZkSpecStruct* latest = &kZkSpecs[0];
        for (int i = 1; i < kNumZkSpecs; i++) {
            if (kZkSpecs[i].version > latest->version) {
                latest = &kZkSpecs[i];
            }
        }
        return latest;
    }

    // Try to parse as index
    try {
        int index = std::stoi(spec_str);
        if (index >= 0 && index < kNumZkSpecs) {
            return &kZkSpecs[index];
        } else {
            throw std::out_of_range("Index out of range");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: Invalid zkspec '" << spec_str << "'. ";
        std::cerr << "Must be 'latest', 'list', or index 0-" << (kNumZkSpecs - 1) << "\n";
        return nullptr;
    }
}

int circuit_gen(const std::string& circuit_file, const std::string& zkspec_str) {
    // Handle list command
    if (zkspec_str == "list") {
        list_zkspecs();
        return 0;
    }

    std::cout << "Generating circuit to: " << circuit_file << "\n";

    try {
        // Find the requested ZK spec
        const auto* zk_spec = find_zkspec(zkspec_str);
        if (!zk_spec) {
            return 1; // Error already printed by find_zkspec
        }

        std::cout << "Using ZK spec: " << zk_spec->system
                  << " (v" << zk_spec->version
                  << ", " << zk_spec->num_attributes << " attributes)\n";
        std::cout << "Circuit hash: " << zk_spec->circuit_hash << "\n";

        uint8_t* circuit_bytes = nullptr;
        size_t circuit_len = 0;

        auto result = generate_circuit(zk_spec, &circuit_bytes, &circuit_len);

        if (result != CIRCUIT_GENERATION_SUCCESS) {
            std::cerr << "Circuit generation failed with error: "
                      << magic_enum::enum_name(result) << "\n";
            return 1;
        }

        // Ensure we got valid output
        if (!circuit_bytes || circuit_len == 0) {
            std::cerr << "Circuit generation returned null or empty circuit\n";
            if (circuit_bytes) free(circuit_bytes);
            return 1;
        }

        // Write circuit to file
        std::ofstream output(circuit_file, std::ios::binary);
        if (!output) {
            std::cerr << "Failed to open output file: " << circuit_file << "\n";
            free(circuit_bytes);
            return 1;
        }

        output.write(reinterpret_cast<const char*>(circuit_bytes), circuit_len);
        if (!output.good()) {
            std::cerr << "Failed to write circuit data to file\n";
            free(circuit_bytes);
            return 1;
        }

        free(circuit_bytes);

        std::cout << "Circuit generated successfully!\n";
        std::cout << "  File: " << circuit_file << "\n";
        std::cout << "  Size: " << circuit_len << " bytes\n";
        std::cout << "  ZK spec: " << zk_spec->system << " v" << zk_spec->version << "\n";
        std::cout << "  Attributes: " << zk_spec->num_attributes << "\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

int mdoc_example() {
    std::cout << "Running mDoc example...\n";

    // Access the first example from mdoc_examples.h
    const auto& example = proofs::mdoc_tests[0];

    std::cout << "Example mDoc data loaded successfully\n";
    std::cout << "Transcript size: " << example.transcript_size << " bytes\n";
    std::cout << "mDoc size: " << example.mdoc_size << " bytes\n";
    std::cout << "Doc type: " << example.doc_type << "\n";

    return 0;
}

int mdoc_prove(const std::string& circuit_file,
               const std::string& mdoc_file,
               const std::string& proof_file) {

    std::cout << "Proving mDoc:\n";
    std::cout << "  Circuit: " << circuit_file << "\n";
    std::cout << "  mDoc: " << mdoc_file << "\n";
    std::cout << "  Proof output: " << proof_file << "\n";

    try {
        // Read mDoc JSON configuration
        std::ifstream mdoc_stream(mdoc_file);
        if (!mdoc_stream) {
            throw std::runtime_error("Cannot open mDoc file: " + mdoc_file);
        }
        json mdoc_json = json::parse(mdoc_stream);

        // Extract mDoc data
        std::string mdoc_data_file = mdoc_json["mdoc_data"];
        std::string transcript_hex = mdoc_json["transcript"];
        std::string pkx_hex = mdoc_json["public_key"]["x"];
        std::string pky_hex = mdoc_json["public_key"]["y"];
        std::string time_str = mdoc_json["time"];
        std::string doc_type = mdoc_json["doc_type"];
        int zkspec_index = mdoc_json.value("zkspec", kNumZkSpecs - 1);

        // Parse requested attributes
        std::vector<RequestedAttribute> attrs;
        if (mdoc_json.contains("attributes")) {
            for (const auto& attr_json : mdoc_json["attributes"]) {
                RequestedAttribute attr = {};
                std::string ns = attr_json["namespace"];
                std::string id = attr_json["id"];
                std::string cbor_hex = attr_json["cbor_value"];

                auto cbor_bytes = encoding::hex_to_bytes(cbor_hex);
                
                std::memcpy(attr.namespace_id, ns.c_str(), std::min(ns.size(), sizeof(attr.namespace_id)));
                std::memcpy(attr.id, id.c_str(), std::min(id.size(), sizeof(attr.id)));
                std::memcpy(attr.cbor_value, cbor_bytes.data(), std::min(cbor_bytes.size(), sizeof(attr.cbor_value)));
                attr.namespace_len = std::min(ns.size(), sizeof(attr.namespace_id));
                attr.id_len = std::min(id.size(), sizeof(attr.id));
                attr.cbor_value_len = std::min(cbor_bytes.size(), sizeof(attr.cbor_value));
                
                attrs.push_back(attr);
            }
        }

        std::cout << "  Doc type: " << doc_type << "\n";
        std::cout << "  Time: " << time_str << "\n";
        std::cout << "  Attributes: " << attrs.size() << "\n";

        // Read files
        auto circuit = FileReader(circuit_file);
        auto mdoc_data = encoding::read_binary_file(mdoc_data_file);
        auto transcript_bytes = encoding::hex_to_bytes(transcript_hex);

        const auto* zk_spec = &kZkSpecs[zkspec_index];
        uint8_t* proof = nullptr;
        size_t proof_len = 0;

        auto result = run_mdoc_prover(
            circuit.data(), circuit.size(),
            mdoc_data.data(), mdoc_data.size(),
            pkx_hex.c_str(), pky_hex.c_str(),
            transcript_bytes.data(), transcript_bytes.size(),
            attrs.data(), attrs.size(),
            time_str.c_str(),
            &proof, &proof_len, zk_spec
        );

        if (result != MDOC_PROVER_SUCCESS) {
            std::cerr << "Prover failed with error: "
                      << magic_enum::enum_name(result) << "\n";
            return 1;
        }

        // Write proof to file
        encoding::write_binary_file(proof_file, proof, proof_len);
        
        // Write proof metadata JSON
        json proof_meta;
        proof_meta["proof_file"] = proof_file;
        proof_meta["proof_size"] = proof_len;
        proof_meta["mdoc_source"] = mdoc_file;
        proof_meta["circuit"] = circuit_file;
        proof_meta["zkspec"] = zkspec_index;
        proof_meta["doc_type"] = doc_type;
        proof_meta["time"] = time_str;
        proof_meta["attributes"] = mdoc_json["attributes"];
        proof_meta["public_key"] = mdoc_json["public_key"];
        proof_meta["transcript"] = transcript_hex;
        
        std::string meta_file = proof_file + ".json";
        std::ofstream meta_out(meta_file);
        meta_out << proof_meta.dump(2);

        free(proof);

        std::cout << "Proof generated successfully (" << proof_len << " bytes)\n";
        std::cout << "Metadata saved to: " << meta_file << "\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

int mdoc_verify(const std::string& circuit_file,
                const std::string& proof_file) {

    std::cout << "Verifying mDoc proof:\n";
    std::cout << "  Circuit: " << circuit_file << "\n";
    std::cout << "  Proof: " << proof_file << "\n";

    try {
        // Read proof metadata JSON
        std::string meta_file = proof_file + ".json";
        std::ifstream meta_stream(meta_file);
        if (!meta_stream) {
            throw std::runtime_error("Cannot open proof metadata file: " + meta_file);
        }
        json proof_meta = json::parse(meta_stream);

        // Extract verification parameters from metadata
        std::string transcript_hex = proof_meta["transcript"];
        std::string pkx_hex = proof_meta["public_key"]["x"];
        std::string pky_hex = proof_meta["public_key"]["y"];
        std::string time_str = proof_meta["time"];
        std::string doc_type = proof_meta["doc_type"];
        int zkspec_index = proof_meta.value("zkspec", kNumZkSpecs - 1);

        // Parse requested attributes
        std::vector<RequestedAttribute> attrs;
        if (proof_meta.contains("attributes")) {
            for (const auto& attr_json : proof_meta["attributes"]) {
                RequestedAttribute attr = {};
                std::string ns = attr_json["namespace"];
                std::string id = attr_json["id"];
                std::string cbor_hex = attr_json["cbor_value"];

                auto cbor_bytes = encoding::hex_to_bytes(cbor_hex);
                
                std::memcpy(attr.namespace_id, ns.c_str(), std::min(ns.size(), sizeof(attr.namespace_id)));
                std::memcpy(attr.id, id.c_str(), std::min(id.size(), sizeof(attr.id)));
                std::memcpy(attr.cbor_value, cbor_bytes.data(), std::min(cbor_bytes.size(), sizeof(attr.cbor_value)));
                attr.namespace_len = std::min(ns.size(), sizeof(attr.namespace_id));
                attr.id_len = std::min(id.size(), sizeof(attr.id));
                attr.cbor_value_len = std::min(cbor_bytes.size(), sizeof(attr.cbor_value));
                
                attrs.push_back(attr);
            }
        }

        std::cout << "  Doc type: " << doc_type << "\n";
        std::cout << "  Time: " << time_str << "\n";
        std::cout << "  Attributes: " << attrs.size() << "\n";

        // Read files
        auto circuit = FileReader(circuit_file);
        auto proof = FileReader(proof_file);
        auto transcript_bytes = encoding::hex_to_bytes(transcript_hex);

        const auto* zk_spec = &kZkSpecs[zkspec_index];

        auto result = run_mdoc_verifier(
            circuit.data(), circuit.size(),
            pkx_hex.c_str(), pky_hex.c_str(),
            transcript_bytes.data(), transcript_bytes.size(),
            attrs.data(), attrs.size(),
            time_str.c_str(),
            proof.data(), proof.size(), doc_type.c_str(),
            zk_spec
        );

        if (result != MDOC_VERIFIER_SUCCESS) {
            std::cerr << "Verification failed with error: "
                      << magic_enum::enum_name(result) << "\n";
            return 1;
        }

        std::cout << "✓ Proof verification successful!\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

} // namespace commands

// Forward declare list function for main
void list_zkspecs() {
    std::cout << "\nAvailable ZK specifications:\n";
    std::cout << "============================\n";
    for (int i = 0; i < kNumZkSpecs; i++) {
        const auto& spec = kZkSpecs[i];
        std::cout << format_string("  [%d] %s v%zu (%zu attributes)\n",
                                 i, spec.system, spec.version, spec.num_attributes);
        std::cout << format_string("      Hash: %s\n", spec.circuit_hash);
        std::cout << "\n";
    }
    std::cout << "Usage examples:\n";
    std::cout << "  --zkspec 0         # Use first spec\n";
    std::cout << "  --zkspec latest    # Use latest spec (default)\n";
    std::cout << "  --zkspec list      # Show this list\n";
}

int main(int argc, char** argv) {
    CLI::App app{"Longfellow-ZK: Zero-Knowledge Proof CLI for mDoc Verification", "longfellow-zk"};
    app.require_subcommand(1);

    // Common options
    std::string circuit_file, proof_file, mdoc_file;
    std::string zkspec_str = "latest"; // Default to latest

    // Circuit generation command
    auto* circuit_gen_cmd = app.add_subcommand("circuit_gen", "Generate ZK circuit");

    circuit_gen_cmd->add_option("--zkspec", zkspec_str,
        "ZK specification to use ('latest', 'list', or index 0-" + std::to_string(kNumZkSpecs-1) + ")")
        ->default_val("latest");

    circuit_gen_cmd->add_option("-c,--circuit", circuit_file, "Output circuit file")
        ->check([](const std::string& file) {
            // For output files, just check if parent directory exists
            auto parent = fs::path(file).parent_path();
            if (!parent.empty() && !fs::exists(parent)) {
                return "Parent directory '" + parent.string() + "' does not exist";
            }
            return std::string{};
        });

    circuit_gen_cmd->callback([&]() {
        // Handle special case for list first
        if (zkspec_str == "list") {
            list_zkspecs();
            return 0;
        }

        // For actual generation, circuit file is required
        if (circuit_file.empty()) {
            std::cerr << "Error: --circuit option is required for circuit generation\n";
            std::cerr << "Use --zkspec list to list available specifications\n";
            return 1;
        }

        return commands::circuit_gen(circuit_file, zkspec_str);
    });

    // mDoc example command
    auto* example_cmd = app.add_subcommand("mdoc_example", "Show mDoc example data");
    example_cmd->callback([&]() {
        return commands::mdoc_example();
    });

    // mDoc prove command
    auto* prove_cmd = app.add_subcommand("mdoc_prove", "Generate ZK proof for mDoc");
    prove_cmd->add_option("-c,--circuit", circuit_file, "Circuit file")->required()->check(CLI::ExistingFile);
    prove_cmd->add_option("-m,--mdoc", mdoc_file, "mDoc JSON file")->required()->check(CLI::ExistingFile);
    prove_cmd->add_option("-p,--proof", proof_file, "Output proof file")->required();

    prove_cmd->callback([&]() {
        return commands::mdoc_prove(circuit_file, mdoc_file, proof_file);
    });

    // mDoc verify command
    auto* verify_cmd = app.add_subcommand("mdoc_verify", "Verify ZK proof for mDoc");
    verify_cmd->add_option("-c,--circuit", circuit_file, "Circuit file")->required()->check(CLI::ExistingFile);
    verify_cmd->add_option("-p,--proof", proof_file, "Proof file (will read proof.bin.json for metadata)")->required()->check(CLI::ExistingFile);

    verify_cmd->callback([&]() {
        return commands::mdoc_verify(circuit_file, proof_file);
    });

    try {
        app.parse(argc, argv);
        return 0;
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
