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

// Extract mdoc examples from mdoc_examples.h and save them as JSON files

#include <cstdio>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <cli/json.hpp>
#include <cli/encoding.h>
#include <circuits/mdoc/mdoc_examples.h>

using namespace proofs;
using json = nlohmann::json;

int main() {
    const size_t num_examples = sizeof(mdoc_tests) / sizeof(mdoc_tests[0]);

    std::cout << "Extracting " << num_examples << " mDoc examples to JSON...\n\n";

    for (size_t i = 0; i < num_examples; i++) {
        const auto& example = mdoc_tests[i];

        // Create filenames
        char mdoc_json_file[256];
        snprintf(mdoc_json_file, sizeof(mdoc_json_file), "mdoc_%02zu.json", i);

        // Create JSON structure
        json mdoc_json;
        mdoc_json["example_id"] = i;
        mdoc_json["mdoc_data_base64"] = encoding::bytes_to_base64(example.mdoc, example.mdoc_size);
        mdoc_json["mdoc_size"] = example.mdoc_size;
        mdoc_json["doc_type"] = example.doc_type ? example.doc_type : "unknown";
        mdoc_json["time"] = example.now ? reinterpret_cast<const char*>(example.now) : "";

        // Public key
        mdoc_json["public_key"]["x"] = example.pkx.as_pointer;
        mdoc_json["public_key"]["y"] = example.pky.as_pointer;

        // Transcript as hex
        mdoc_json["transcript"] = encoding::bytes_to_hex(example.transcript, example.transcript_size);

        // Default zkspec (will be overridden based on attribute count)
        mdoc_json["zkspec"] = 11; // Default to latest

        // Attributes - add example attributes based on the doc_type
        mdoc_json["attributes"] = json::array();

        // For example 0, we know it has age_over_18
        if (i == 0) {
            json attr;
            attr["namespace"] = "org.iso.18013.5.1";
            attr["id"] = "age_over_18";
            attr["cbor_value"] = "0xf5"; // CBOR true
            mdoc_json["attributes"].push_back(attr);
        }
        // TODO: Parse other examples to extract their attributes automatically

        // Add metadata
        mdoc_json["_metadata"] = {
            {"description", "Extracted from mdoc_examples.h"},
            {"example_number", i},
            {"transcript_size", example.transcript_size},
            {"note", "mdoc data is available both as separate .bin file and as base64 in mdoc_data_base64"}
        };

        // Write JSON file
        std::ofstream json_out(mdoc_json_file);
        if (!json_out) {
            std::cerr << "Failed to create " << mdoc_json_file << "\n";
            return 1;
        }
        json_out << mdoc_json.dump(2);
        json_out.close();

        std::cout << "Example " << std::setfill('0') << std::setw(2) << i
                  << ": " << example.mdoc_size << " bytes → " << mdoc_json_file
                  << " (doc_type: " << (example.doc_type ? example.doc_type : "unknown") << ")\n";
    }

    std::cout << "\nAll examples extracted as JSON to test/ directory\n";
    std::cout << "  JSON config: mdoc_XX.json\n";
    return 0;
}
