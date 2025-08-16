/*
 * Copyright (C) 2025 Dyne.org foundation
 * designed, written and maintained by Denis Roio <jaromil@dyne.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
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
#include <magic_enum.hpp>
#include <circuits/mdoc/mdoc_zk.h>
#include <circuits/mdoc/mdoc_examples.h>

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
        return &kZkSpecs[kNumZkSpecs - 1];
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
               const std::string& proof_file,
               const std::string& public_key_file,
               const std::string& transcript_file,
               const std::string& time_str,
               const std::string& doc_type) {

    std::cout << "Proving mDoc with:\n";
    std::cout << "  Circuit: " << circuit_file << "\n";
    std::cout << "  Proof output: " << proof_file << "\n";
    std::cout << "  Public key: " << public_key_file << "\n";
    std::cout << "  Transcript: " << transcript_file << "\n";
    std::cout << "  Time: " << time_str << "\n";
    std::cout << "  Doc type: " << doc_type << "\n";

    try {
        auto circuit = FileReader(circuit_file);
        auto transcript = FileReader(transcript_file);

        // For demo purposes, use the first example data
        const auto& example = proofs::mdoc_tests[0];

        const auto* zk_spec = &kZkSpecs[kNumZkSpecs - 1];
        uint8_t* proof = nullptr;
        size_t proof_len = 0;

        // Create a simple RequestedAttribute for demo (age_over_18)
        RequestedAttribute attrs[1];
        const char* attr_id = "age_over_18";
        const char* attr_value = "true";
        std::memcpy(attrs[0].id, attr_id, std::min(strlen(attr_id), sizeof(attrs[0].id)));
        std::memcpy(attrs[0].value, attr_value, std::min(strlen(attr_value), sizeof(attrs[0].value)));
        attrs[0].id_len = std::min(strlen(attr_id), sizeof(attrs[0].id));
        attrs[0].value_len = std::min(strlen(attr_value), sizeof(attrs[0].value));
        attrs[0].type = kPrimitive;

        auto result = run_mdoc_prover(
            circuit.data(), circuit.size(),
            example.mdoc, example.mdoc_size,
            example.pkx.as_pointer, example.pky.as_pointer,
            transcript.data(), transcript.size(),
            attrs, 1,
            time_str.c_str(),
            &proof, &proof_len, zk_spec
        );

        if (result != MDOC_PROVER_SUCCESS) {
            std::cerr << "Prover failed with error: "
                      << magic_enum::enum_name(result) << "\n";
            return 1;
        }

        // Write proof to file
        std::ofstream output(proof_file, std::ios::binary);
        if (!output) {
            std::cerr << "Failed to open proof output file: " << proof_file << "\n";
            free(proof);
            return 1;
        }

        output.write(reinterpret_cast<const char*>(proof), proof_len);
        free(proof);

        std::cout << "Proof generated successfully (" << proof_len << " bytes)\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

int mdoc_verify(const std::string& circuit_file,
                const std::string& proof_file,
                const std::string& public_key_file,
                const std::string& transcript_file,
                const std::string& time_str,
                const std::string& doc_type) {

    std::cout << "Verifying mDoc proof with:\n";
    std::cout << "  Circuit: " << circuit_file << "\n";
    std::cout << "  Proof: " << proof_file << "\n";
    std::cout << "  Public key: " << public_key_file << "\n";
    std::cout << "  Transcript: " << transcript_file << "\n";
    std::cout << "  Time: " << time_str << "\n";
    std::cout << "  Doc type: " << doc_type << "\n";

    try {
        auto circuit = FileReader(circuit_file);
        auto proof = FileReader(proof_file);
        auto transcript = FileReader(transcript_file);

        // For demo purposes, use the first example data
        const auto& example = proofs::mdoc_tests[0];

        const auto* zk_spec = &kZkSpecs[kNumZkSpecs - 1];

        // Create the same RequestedAttribute as in prove
        RequestedAttribute attrs[1];
        const char* attr_id = "age_over_18";
        const char* attr_value = "true";
        std::memcpy(attrs[0].id, attr_id, std::min(strlen(attr_id), sizeof(attrs[0].id)));
        std::memcpy(attrs[0].value, attr_value, std::min(strlen(attr_value), sizeof(attrs[0].value)));
        attrs[0].id_len = std::min(strlen(attr_id), sizeof(attrs[0].id));
        attrs[0].value_len = std::min(strlen(attr_value), sizeof(attrs[0].value));
        attrs[0].type = kPrimitive;

        auto result = run_mdoc_verifier(
            circuit.data(), circuit.size(),
            example.pkx.as_pointer, example.pky.as_pointer,
            transcript.data(), transcript.size(),
            attrs, 1,
            time_str.c_str(),
            proof.data(), proof.size(), doc_type.c_str(),
            zk_spec
        );

        if (result != MDOC_VERIFIER_SUCCESS) {
            std::cerr << "Verification failed with error: "
                      << magic_enum::enum_name(result) << "\n";
            return 1;
        }

        std::cout << "Proof verification successful!\n";
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

    // Common options with file validation
    std::string circuit_file, proof_file, public_key_file, transcript_file, time_str, doc_type;
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
    prove_cmd->add_option("-p,--proof", proof_file, "Output proof file")->required();
    prove_cmd->add_option("--pk,--public-key", public_key_file, "Public key file")->required()->check(CLI::ExistingFile);
    prove_cmd->add_option("-s,--transcript", transcript_file, "Session transcript file")->required()->check(CLI::ExistingFile);
    prove_cmd->add_option("-t,--time", time_str, "Time string (ISO 8601 format)")->required();
    prove_cmd->add_option("-d,--doc-type", doc_type, "Document type")->required();

    prove_cmd->callback([&]() {
        return commands::mdoc_prove(circuit_file, proof_file, public_key_file,
                                   transcript_file, time_str, doc_type);
    });

    // mDoc verify command
    auto* verify_cmd = app.add_subcommand("mdoc_verify", "Verify ZK proof for mDoc");
    verify_cmd->add_option("-c,--circuit", circuit_file, "Circuit file")->required()->check(CLI::ExistingFile);
    verify_cmd->add_option("-p,--proof", proof_file, "Proof file")->required()->check(CLI::ExistingFile);
    verify_cmd->add_option("--pk,--public-key", public_key_file, "Public key file")->required()->check(CLI::ExistingFile);
    verify_cmd->add_option("-s,--transcript", transcript_file, "Session transcript file")->required()->check(CLI::ExistingFile);
    verify_cmd->add_option("-t,--time", time_str, "Time string (ISO 8601 format)")->required();
    verify_cmd->add_option("-d,--doc-type", doc_type, "Document type")->required();

    verify_cmd->callback([&]() {
        return commands::mdoc_verify(circuit_file, proof_file, public_key_file,
                                    transcript_file, time_str, doc_type);
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
