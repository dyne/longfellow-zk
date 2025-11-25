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

// Extract mdoc examples from mdoc_examples.h and save them as binary files

#include <cstdio>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>

#include "circuits/mdoc/mdoc_examples.h"

using namespace proofs;

int main() {
    const size_t num_examples = sizeof(mdoc_tests) / sizeof(mdoc_tests[0]);

    std::cout << "Extracting " << num_examples << " mDoc examples...\n\n";

    for (size_t i = 0; i < num_examples; i++) {
        const auto& example = mdoc_tests[i];

        // Create filenames
        char mdoc_file[256];
        char meta_file[256];
        char transcript_file[256];
        char pkx_file[256];
        char pky_file[256];
        snprintf(mdoc_file, sizeof(mdoc_file), "mdoc_%02zu.bin", i);
        snprintf(meta_file, sizeof(meta_file), "mdoc_%02zu.txt", i);
        snprintf(transcript_file, sizeof(transcript_file), "transcript_%02zu.bin", i);
        snprintf(pkx_file, sizeof(pkx_file), "pkx_%02zu.txt", i);
        snprintf(pky_file, sizeof(pky_file), "pky_%02zu.txt", i);

        // Write mDoc binary data
        std::ofstream mdoc_out(mdoc_file, std::ios::binary);
        if (!mdoc_out) {
            std::cerr << "Failed to create " << mdoc_file << "\n";
            return 1;
        }
        mdoc_out.write(reinterpret_cast<const char*>(example.mdoc), example.mdoc_size);
        mdoc_out.close();

        // Write transcript binary data
        std::ofstream transcript_out(transcript_file, std::ios::binary);
        if (!transcript_out) {
            std::cerr << "Failed to create " << transcript_file << "\n";
            return 1;
        }
        transcript_out.write(reinterpret_cast<const char*>(example.transcript), example.transcript_size);
        transcript_out.close();

        // Write public key X
        std::ofstream pkx_out(pkx_file);
        if (!pkx_out) {
            std::cerr << "Failed to create " << pkx_file << "\n";
            return 1;
        }
        pkx_out << example.pkx.as_pointer << "\n";
        pkx_out.close();

        // Write public key Y
        std::ofstream pky_out(pky_file);
        if (!pky_out) {
            std::cerr << "Failed to create " << pky_file << "\n";
            return 1;
        }
        pky_out << example.pky.as_pointer << "\n";
        pky_out.close();

        // Write metadata
        std::ofstream meta_out(meta_file);
        if (!meta_out) {
            std::cerr << "Failed to create " << meta_file << "\n";
            return 1;
        }

        meta_out << "mDoc Example #" << i << "\n";
        meta_out << "===================\n\n";
        meta_out << "File: mdoc_" << std::setfill('0') << std::setw(2) << i << ".bin\n";
        meta_out << "Size: " << example.mdoc_size << " bytes\n";
        meta_out << "Doc Type: " << (example.doc_type ? example.doc_type : "unknown") << "\n";
        meta_out << "Timestamp: " << (example.now ? reinterpret_cast<const char*>(example.now) : "none") << "\n\n";

        meta_out << "Issuer Public Key X:\n  " << example.pkx.as_pointer << "\n";
        meta_out << "Issuer Public Key Y:\n  " << example.pky.as_pointer << "\n\n";

        meta_out << "Transcript (" << example.transcript_size << " bytes):\n  ";
        for (size_t j = 0; j < example.transcript_size && j < 64; j++) {
            meta_out << std::hex << std::setfill('0') << std::setw(2)
                     << static_cast<int>(example.transcript[j]);
            if (j < example.transcript_size - 1 && j < 63) meta_out << " ";
        }
        if (example.transcript_size > 64) {
            meta_out << " ...";
        }
        meta_out << "\n";
        meta_out.close();

        std::cout << "✓ Example " << std::setfill('0') << std::setw(2) << i
                  << ": " << example.mdoc_size << " bytes"
                  << " (doc_type: " << (example.doc_type ? example.doc_type : "unknown") << ")\n";
    }

    std::cout << "\n✓ All examples extracted to test/ directory\n";
    return 0;
}
