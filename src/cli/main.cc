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
#include <ctime>

#include "CLI11.hpp"
#include "json.hpp"
#include "encoding.h"
#include "nanobench.h"
#include <magic_enum.hpp>
#include <circuits/mdoc/mdoc_zk.h>

using json = nlohmann::json;
namespace nb = ankerl::nanobench;

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

// Global benchmark file path (set by --benchmark flag)
static std::string g_benchmark_file = "";

// Helper to run benchmark conditionally and output to file
template<typename Func>
void run_benchmark_if_enabled(const std::string& title, const std::string& unit,
                               const std::string& name, Func&& func) {
    if (g_benchmark_file.empty()) {
        // Benchmarking disabled, just run the function once
        func();
        return;
    }

    // Benchmarking enabled - run with nanobench and capture to file
    std::ofstream bench_file(g_benchmark_file, std::ios::app);
    if (!bench_file) {
        std::cerr << "Warning: Failed to open benchmark file: " << g_benchmark_file << "\n";
        // Still run the function even if we can't write benchmark
        func();
        return;
    }

    // Add timestamp header
    auto now = std::time(nullptr);
    char timestamp[100];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    bench_file << "# " << timestamp << " - " << title << "\n";

    // Create benchmark and redirect output to file
    nb::Bench bench;
    bench.title(title)
         .unit(unit)
         .warmup(0)
         .epochs(1)
         .minEpochIterations(1)
         .relative(false)
         .timeUnit(std::chrono::seconds(1), "s")
         .output(&bench_file);  // Output directly to file

    bench.run(name, std::forward<Func>(func));

    bench_file << "\n";  // Add blank line after benchmark
    bench_file.flush();
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

        // Find zkspec index
        int zkspec_index = -1;
        for (int i = 0; i < kNumZkSpecs; i++) {
            if (&kZkSpecs[i] == zk_spec) {
                zkspec_index = i;
                break;
            }
        }

        std::cout << "Using ZK spec: " << zk_spec->system
                  << " (v" << zk_spec->version
                  << ", " << zk_spec->num_attributes << " attributes)\n";
        std::cout << "Circuit hash: " << zk_spec->circuit_hash << "\n";

        uint8_t* circuit_bytes = nullptr;
        size_t circuit_len = 0;
        CircuitGenerationErrorCode result;

        // Conditionally benchmark circuit generation
        run_benchmark_if_enabled(
            "Circuit Generation",
            "circuit",
            std::string("zkspec_") + std::to_string(zkspec_index) +
                "_" + std::to_string(zk_spec->num_attributes) + "attr",
            [&] {
                result = generate_circuit(zk_spec, &circuit_bytes, &circuit_len);
                nb::doNotOptimizeAway(circuit_bytes);
            }
        );

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

        // Create circuit JSON
        json circuit_json;
        circuit_json["circuit_data_base64"] = encoding::bytes_to_base64(circuit_bytes, circuit_len);
        circuit_json["_circuit_size"] = circuit_len;
        circuit_json["_zkspec"] = {
            {"index", zkspec_index},
            {"system", zk_spec->system},
            {"version", zk_spec->version},
            {"num_attributes", zk_spec->num_attributes},
            {"circuit_hash", zk_spec->circuit_hash}
        };
        circuit_json["_generated"] = std::time(nullptr);
        circuit_json["_metadata"] = {
            {"description", "ZK circuit for mDoc verification"},
            {"format", "LFC1"},
            {"storage_format", "LFC1"},
            {"rollback", "LFC1 is the legacy/default format; LFC2 is opt-in where the producer exposes it"}
        };

        // Write circuit JSON to file
        std::ofstream output(circuit_file);
        if (!output) {
            std::cerr << "Failed to open output file: " << circuit_file << "\n";
            free(circuit_bytes);
            return 1;
        }

        output << circuit_json.dump(2);
        if (!output.good()) {
            std::cerr << "Failed to write circuit JSON to file\n";
            free(circuit_bytes);
            return 1;
        }

        free(circuit_bytes);

        std::cout << "Circuit generated successfully!\n";
        std::cout << "  File: " << circuit_file << "\n";
        std::cout << "  Binary size: " << circuit_len << " bytes\n";
        std::cout << "  ZK spec: " << zk_spec->system << " v" << zk_spec->version << "\n";
        std::cout << "  Attributes: " << zk_spec->num_attributes << "\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

int mdoc_prove(const std::string& circuit_file,
               const std::string& mdoc_file,
               const std::string& proof_file) {

    std::cout << "Proving mDoc:\n";
    std::cout << "  Circuit: " << circuit_file << "\n";
    std::cout << "  mDoc: " << mdoc_file << "\n";
    std::cout << "  Proof output: " << proof_file << "\n";

    try {
        // Read circuit JSON
        std::ifstream circuit_stream(circuit_file);
        if (!circuit_stream) {
            throw std::runtime_error("Cannot open circuit file: " + circuit_file);
        }
        json circuit_json = json::parse(circuit_stream);

        // Extract circuit data
        auto circuit_data = encoding::base64_to_bytes(circuit_json["circuit_data_base64"]);
        int circuit_zkspec_index = circuit_json["_zkspec"]["index"];

        // Read mDoc JSON configuration
        std::ifstream mdoc_stream(mdoc_file);
        if (!mdoc_stream) {
            throw std::runtime_error("Cannot open mDoc file: " + mdoc_file);
        }
        json mdoc_json = json::parse(mdoc_stream);

        // Extract mDoc data - prefer base64 from JSON
        std::vector<uint8_t> mdoc_data;
        if (mdoc_json.contains("mdoc_data_base64")) {
            mdoc_data = encoding::base64_to_bytes(mdoc_json["mdoc_data_base64"]);
        } else if (mdoc_json.contains("mdoc_data")) {
            std::string mdoc_data_file = mdoc_json["mdoc_data"];
            mdoc_data = encoding::read_binary_file(mdoc_data_file);
        } else {
            throw std::runtime_error("mDoc JSON must contain either mdoc_data_base64 or mdoc_data");
        }

        std::string transcript_hex = mdoc_json["transcript"];
        std::string pkx_hex = mdoc_json["public_key"]["x"];
        std::string pky_hex = mdoc_json["public_key"]["y"];
        std::string time_str = mdoc_json["time"];
        std::string doc_type = mdoc_json["doc_type"];
        int mdoc_zkspec_index = mdoc_json.value("zkspec", kNumZkSpecs - 1);

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

        // Dummy attribute for empty case (C API requires non-null pointer)
        RequestedAttribute dummy_attr = {};
        const RequestedAttribute* attrs_ptr = attrs.empty() ? &dummy_attr : attrs.data();
        size_t attrs_len = attrs.size();

        std::cout << "  Doc type: " << doc_type << "\n";
        std::cout << "  Time: " << time_str << "\n";
        std::cout << "  Attributes: " << attrs_len << "\n";
        std::cout << "  Circuit zkspec index: " << circuit_zkspec_index << "\n";
        std::cout << "  mDoc requires zkspec index: " << mdoc_zkspec_index << "\n";

        // Verify circuit matches mdoc requirement
        if (circuit_zkspec_index != mdoc_zkspec_index) {
            std::cerr << "Error: Circuit zkspec (" << circuit_zkspec_index
                      << ") does not match mDoc requirement (" << mdoc_zkspec_index << ")\n";
            return 1;
        }

        // Read transcript
        auto transcript_bytes = encoding::hex_to_bytes(transcript_hex);

        // Use the mdoc's zkspec (which should match the circuit)
        const auto* zk_spec = &kZkSpecs[mdoc_zkspec_index];
        uint8_t* proof = nullptr;
        size_t proof_len = 0;
        MdocProverErrorCode result;

        // Conditionally benchmark proof generation
        run_benchmark_if_enabled(
            "Proof Generation",
            "proof",
            std::string("zkspec_") + std::to_string(mdoc_zkspec_index) +
                "_" + std::to_string(attrs_len) + "attr",
            [&] {
                result = run_mdoc_prover(
                    circuit_data.data(), circuit_data.size(),
                    mdoc_data.data(), mdoc_data.size(),
                    pkx_hex.c_str(), pky_hex.c_str(),
                    transcript_bytes.data(), transcript_bytes.size(),
                    attrs_ptr, attrs_len,
                    time_str.c_str(),
                    &proof, &proof_len, zk_spec
                );
                nb::doNotOptimizeAway(proof);
            }
        );

        if (result != MDOC_PROVER_SUCCESS) {
            std::cerr << "Prover failed with error: "
                      << magic_enum::enum_name(result) << "\n";
            return 1;
        }

        // Create proof JSON with embedded binary data and full metadata
        json proof_json;
        proof_json["proof_data_base64"] = encoding::bytes_to_base64(proof, proof_len);
        proof_json["proof_size"] = proof_len;
        proof_json["circuit_number"] = circuit_zkspec_index;
        proof_json["mdoc_source"] = mdoc_file;
        proof_json["circuit_source"] = circuit_file;
        proof_json["zkspec"] = mdoc_zkspec_index;
        proof_json["doc_type"] = doc_type;
        proof_json["time"] = time_str;
        proof_json["attributes"] = mdoc_json["attributes"];
        proof_json["public_key"] = mdoc_json["public_key"];
        proof_json["transcript"] = transcript_hex;
        proof_json["generated"] = std::time(nullptr);
        proof_json["_metadata"] = {
            {"description", "ZK proof for mDoc verification"},
            {"format", "base64-encoded proof data"}
        };

        // Write proof JSON
        std::ofstream proof_out(proof_file);
        if (!proof_out) {
            std::cerr << "Failed to open proof output file: " << proof_file << "\n";
            free(proof);
            return 1;
        }
        proof_out << proof_json.dump(2);
        if (!proof_out.good()) {
            std::cerr << "Failed to write proof JSON to file\n";
            free(proof);
            return 1;
        }

        free(proof);

        std::cout << "Proof generated successfully (" << proof_len << " bytes)\n";
        std::cout << "Proof saved to: " << proof_file << "\n";
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
        // Read circuit JSON
        std::ifstream circuit_stream(circuit_file);
        if (!circuit_stream) {
            throw std::runtime_error("Cannot open circuit file: " + circuit_file);
        }
        json circuit_json = json::parse(circuit_stream);
        auto circuit_data = encoding::base64_to_bytes(circuit_json["circuit_data_base64"]);

        // Read proof JSON
        std::ifstream proof_stream(proof_file);
        if (!proof_stream) {
            throw std::runtime_error("Cannot open proof file: " + proof_file);
        }
        json proof_json = json::parse(proof_stream);

        // Extract verification parameters from proof JSON
        auto proof_data = encoding::base64_to_bytes(proof_json["proof_data_base64"]);
        std::string transcript_hex = proof_json["transcript"];
        std::string pkx_hex = proof_json["public_key"]["x"];
        std::string pky_hex = proof_json["public_key"]["y"];
        std::string time_str = proof_json["time"];
        std::string doc_type = proof_json["doc_type"];
        int zkspec_index = proof_json.value("zkspec", kNumZkSpecs - 1);

        // Parse requested attributes
        std::vector<RequestedAttribute> attrs;
        if (proof_json.contains("attributes")) {
            for (const auto& attr_json : proof_json["attributes"]) {
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

        // Dummy attribute for empty case (C API requires non-null pointer)
        RequestedAttribute dummy_attr = {};
        const RequestedAttribute* attrs_ptr = attrs.empty() ? &dummy_attr : attrs.data();
        size_t attrs_len = attrs.size();

        std::cout << "  Doc type: " << doc_type << "\n";
        std::cout << "  Time: " << time_str << "\n";
        std::cout << "  Attributes: " << attrs_len << "\n";

        // Decode transcript
        auto transcript_bytes = encoding::hex_to_bytes(transcript_hex);

        const auto* zk_spec = &kZkSpecs[zkspec_index];
        MdocVerifierErrorCode result;

        // Conditionally benchmark proof verification
        run_benchmark_if_enabled(
            "Proof Verification",
            "verification",
            std::string("zkspec_") + std::to_string(zkspec_index) +
                "_" + std::to_string(attrs_len) + "attr",
            [&] {
                result = run_mdoc_verifier(
                    circuit_data.data(), circuit_data.size(),
                    pkx_hex.c_str(), pky_hex.c_str(),
                    transcript_bytes.data(), transcript_bytes.size(),
                    attrs_ptr, attrs_len,
                    time_str.c_str(),
                    proof_data.data(), proof_data.size(), doc_type.c_str(),
                    zk_spec
                );
                nb::doNotOptimizeAway(result);
            }
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
    std::string benchmark_file = ""; // Benchmark output file (empty = disabled)
    int command_result = 0; // Store result from command callbacks

    // Global benchmark flag
    app.add_option("--benchmark", benchmark_file,
        "Enable benchmarking and append results to specified file");

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
        // Set global benchmark file
        g_benchmark_file = benchmark_file;

        // Handle special case for list first
        if (zkspec_str == "list") {
            list_zkspecs();
            command_result = 0;
            return;
        }

        // For actual generation, circuit file is required
        if (circuit_file.empty()) {
            std::cerr << "Error: --circuit option is required for circuit generation\n";
            std::cerr << "Use --zkspec list to list available specifications\n";
            command_result = 1;
            return;
        }

        command_result = commands::circuit_gen(circuit_file, zkspec_str);
    });

    // mDoc prove command
    auto* prove_cmd = app.add_subcommand("mdoc_prove", "Generate ZK proof for mDoc");
    prove_cmd->add_option("-c,--circuit", circuit_file, "Circuit file")->required()->check(CLI::ExistingFile);
    prove_cmd->add_option("-m,--mdoc", mdoc_file, "mDoc JSON file")->required()->check(CLI::ExistingFile);
    prove_cmd->add_option("-p,--proof", proof_file, "Output proof file")->required();

    prove_cmd->callback([&]() {
        g_benchmark_file = benchmark_file;
        command_result = commands::mdoc_prove(circuit_file, mdoc_file, proof_file);
    });

    // mDoc verify command
    auto* verify_cmd = app.add_subcommand("mdoc_verify", "Verify ZK proof for mDoc");
    verify_cmd->add_option("-c,--circuit", circuit_file, "Circuit file")->required()->check(CLI::ExistingFile);
    verify_cmd->add_option("-p,--proof", proof_file, "Proof file (will read proof.bin.json for metadata)")->required()->check(CLI::ExistingFile);

    verify_cmd->callback([&]() {
        g_benchmark_file = benchmark_file;
        command_result = commands::mdoc_verify(circuit_file, proof_file);
    });

    try {
        app.parse(argc, argv);
        return command_result;
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
