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

        // Determine zkspec and attributes based on example
        // Attribute information extracted from mdoc_zk_test.cc and mdoc_test_attributes.h
        mdoc_json["attributes"] = json::array();

        auto add_attr = [&](const char* ns, const char* id, const char* cbor_hex) {
            json attr;
            attr["namespace"] = ns;
            attr["id"] = id;
            attr["cbor_value"] = cbor_hex;
            mdoc_json["attributes"].push_back(attr);
        };

        switch (i) {
            case 0:  // age_over_18
            case 1:  // age_over_18
            case 2:  // age_over_18
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute
                add_attr("org.iso.18013.5.1", "age_over_18", "0xf5");
                break;

            case 3:  // Multiple attributes available: familyname, birthdate, height
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute - using familyname
                add_attr("org.iso.18013.5.1", "family_name", "0x6a4d75737465726d616e6e");
                break;

            case 4:  // birthdate_1998_09_04 (Google IDPass, different docType)
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute
                add_attr("org.iso.18013.5.1", "birth_date", "0xd903ec6a313939382d30392d3034");
                break;

            case 5:  // age_over_18 (website explainer example)
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute
                add_attr("org.iso.18013.5.1", "age_over_18", "0xf5");
                break;

            case 6:  // not_over_18 (large mdoc, value is false)
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute
                add_attr("org.iso.18013.5.1", "age_over_18", "0xf4");  // CBOR false
                break;

            case 7:  // birthdate_1968_04_27, issue_date (has 2 attrs, but we can use 1)
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute
                add_attr("org.iso.18013.5.1", "birth_date", "0xd903ec6a313936382d30342d3237");
                break;

            case 8:  // age_birth_year (integer field)
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute
                add_attr("org.iso.18013.5.1", "age_birth_year", "0x1907b0");
                break;

            case 9:  // europa_age_over_18 (EU namespace)
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute
                add_attr("eu.europa.ec.av.1", "age_over_18", "0xf5");
                break;

            case 10:  // aamva_dhs_compliance
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute
                add_attr("org.iso.18013.5.aamva", "DHS_compliance", "0x6146");
                break;

            case 11:  // age_over_18 (Sparkasse Age Assurance)
                mdoc_json["zkspec"] = 0;  // v6, 1 attribute
                add_attr("eu.europa.ec.av.1", "age_over_18", "0xf5");
                break;

            default:
                mdoc_json["zkspec"] = 0;
                break;
        }

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

    std::cout << "\n✓ All examples extracted as JSON to test/ directory\n";
    std::cout << "  JSON files: mdoc_XX.json (with embedded base64 mDoc data)\n";
    return 0;
}
