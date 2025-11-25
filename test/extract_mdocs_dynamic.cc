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

// Extract mdoc examples from mdoc_examples.h with DYNAMIC attribute parsing

#include <cstdio>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <cli/json.hpp>
#include <cli/encoding.h>
#include <circuits/mdoc/mdoc_examples.h>
#include <circuits/mdoc/mdoc_witness.h>

using namespace proofs;
using json = nlohmann::json;

// Helper to convert bytes to hex string
std::string bytes_to_hex_prefixed(const uint8_t* data, size_t len) {
    if (len == 0) return "0x";
    std::ostringstream oss;
    oss << "0x";
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) 
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

int main() {
    const size_t num_examples = sizeof(mdoc_tests) / sizeof(mdoc_tests[0]);

    std::cout << "Extracting " << num_examples << " mDoc examples with DYNAMIC attribute parsing...\n\n";

    for (size_t i = 0; i < num_examples; i++) {
        const auto& example = mdoc_tests[i];

        // Create filenames
        char mdoc_json_file[256];
        snprintf(mdoc_json_file, sizeof(mdoc_json_file), "mdoc_%02zu.json", i);

        // Parse the mDoc to extract attributes dynamically
        ParsedMdoc pm;
        bool ok = pm.parse_device_response(example.mdoc_size, example.mdoc);
        
        if (!ok) {
            std::cerr << "Warning: Failed to parse mdoc " << i << ", skipping attribute extraction\n";
        }

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

        // Dynamically extracted attributes
        mdoc_json["attributes"] = json::array();
        
        if (ok && !pm.attributes_.empty()) {
            // Determine zkspec based on number of attributes
            // v6 (latest): indices 0-3 for 1-4 attributes
            size_t num_attrs = pm.attributes_.size();
            if (num_attrs >= 1 && num_attrs <= 4) {
                mdoc_json["zkspec"] = static_cast<int>(num_attrs - 1);  // 0 for 1 attr, 1 for 2 attrs, etc.
            } else {
                mdoc_json["zkspec"] = 0;  // Default to 1 attribute circuit
            }
            
            std::cout << "Example " << std::setfill('0') << std::setw(2) << i
                      << ": Found " << pm.attributes_.size() << " attributes\n";
            
            // For simplicity, extract only the first attribute
            // (tests can be extended to use multiple attributes for circuits that support it)
            const auto& attr = pm.attributes_[0];
            
            json attr_json;
            // Namespace
            attr_json["namespace"] = std::string(reinterpret_cast<const char*>(attr.mdl_ns));
            
            // Attribute ID
            attr_json["id"] = std::string(
                reinterpret_cast<const char*>(&attr.doc[attr.id_ind]), 
                attr.id_len
            );
            
            // Attribute value (CBOR-encoded)
            // Need to include CBOR type prefix, which starts 1 byte before val_ind
            // The CBOR value includes the type byte at [val_ind - 1]
            attr_json["cbor_value"] = bytes_to_hex_prefixed(
                &attr.doc[attr.val_ind - 1],  // Include CBOR type byte
                attr.val_len + 1               // Length + type byte
            );
            
            mdoc_json["attributes"].push_back(attr_json);
            
            std::cout << "    - " << attr_json["namespace"] << ":"
                      << attr_json["id"] << " = " << attr_json["cbor_value"] << "\n";
        } else {
            // No attributes or parse failed - default to zkspec 0
            mdoc_json["zkspec"] = 0;
            std::cout << "Example " << std::setfill('0') << std::setw(2) << i
                      << ": No attributes extracted (parse " << (ok ? "OK" : "FAILED") << ")\n";
        }

        // Add metadata
        mdoc_json["_metadata"] = {
            {"description", "Extracted from mdoc_examples.h with dynamic CBOR parsing"},
            {"example_number", i},
            {"transcript_size", example.transcript_size},
            {"extraction_method", "ParsedMdoc CBOR parser"},
            {"total_attributes_in_mdoc", ok ? pm.attributes_.size() : 0},
            {"note", "Only first attribute is exported for testing; mDoc may contain more"}
        };

        // Write JSON file
        std::ofstream json_out(mdoc_json_file);
        if (!json_out) {
            std::cerr << "Failed to create " << mdoc_json_file << "\n";
            return 1;
        }
        json_out << mdoc_json.dump(2);
        json_out.close();
    }

    std::cout << "\n✓ All " << num_examples << " examples extracted with dynamic attribute parsing!\n";
    std::cout << "  JSON files: mdoc_XX.json (with parsed attributes from CBOR)\n";
    std::cout << "  Future additions to mdoc_examples.h will be automatically extracted.\n";
    return 0;
}
