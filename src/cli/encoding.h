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

#ifndef PRIVACY_PROOFS_CLI_ENCODING_H_
#define PRIVACY_PROOFS_CLI_ENCODING_H_

#include <string>
#include <vector>
#include <cstdint>

namespace encoding {

// Hex encoding/decoding
std::vector<uint8_t> hex_to_bytes(const std::string& hex);
std::string bytes_to_hex(const uint8_t* data, size_t len);

// Base64 encoding/decoding
std::vector<uint8_t> base64_to_bytes(const std::string& base64_str);
std::string bytes_to_base64(const uint8_t* data, size_t len);

// File I/O
std::vector<uint8_t> read_binary_file(const std::string& filename);
void write_binary_file(const std::string& filename, const uint8_t* data, size_t len);

} // namespace encoding

#endif  // PRIVACY_PROOFS_CLI_ENCODING_H_
