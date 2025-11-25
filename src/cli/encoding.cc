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

#include "encoding.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <cstring>

namespace encoding {

// Convert hex string to bytes
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::string clean_hex = hex;

    // Remove "0x" prefix if present
    if (clean_hex.size() >= 2 && clean_hex[0] == '0' && (clean_hex[1] == 'x' || clean_hex[1] == 'X')) {
        clean_hex = clean_hex.substr(2);
    }

    // Remove spaces
    clean_hex.erase(std::remove(clean_hex.begin(), clean_hex.end(), ' '), clean_hex.end());

    for (size_t i = 0; i < clean_hex.length(); i += 2) {
        std::string byte_str = clean_hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtoul(byte_str.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

// Convert bytes to hex string
std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << "0x";
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

// Convert base64 string to bytes
std::vector<uint8_t> base64_to_bytes(const std::string& base64_str) {
    static const uint8_t base64_decode_table[256] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    std::vector<uint8_t> result;
    result.reserve(base64_str.length() * 3 / 4);

    for (size_t i = 0; i < base64_str.length(); i += 4) {
        uint32_t val = 0;
        int padding = 0;

        // Read all 4 characters in this block, always shift 6 bits
        for (int j = 0; j < 4; j++) {
            val <<= 6;
            if (i + j < base64_str.length()) {
                char c = base64_str[i + j];
                if (c == '=') {
                    padding++;
                } else {
                    val |= base64_decode_table[static_cast<uint8_t>(c)];
                }
            }
        }

        // Decode based on padding:
        // No padding (XXXX) -> 3 bytes
        // One = (XXX=) -> 2 bytes
        // Two == (XX==) -> 1 byte
        result.push_back((val >> 16) & 0xFF);
        if (padding <= 1) result.push_back((val >> 8) & 0xFF);
        if (padding == 0) result.push_back(val & 0xFF);
    }

    return result;
}

// Convert bytes to base64 string
std::string bytes_to_base64(const uint8_t* data, size_t len) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string result;
    result.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t val = data[i] << 16;
        if (i + 1 < len) val |= data[i + 1] << 8;
        if (i + 2 < len) val |= data[i + 2];

        result.push_back(base64_chars[(val >> 18) & 0x3F]);
        result.push_back(base64_chars[(val >> 12) & 0x3F]);
        result.push_back((i + 1 < len) ? base64_chars[(val >> 6) & 0x3F] : '=');
        result.push_back((i + 2 < len) ? base64_chars[val & 0x3F] : '=');
    }

    return result;
}

// Read binary file
std::vector<uint8_t> read_binary_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filename);
    }

    size_t size = file.tellg();
    std::vector<uint8_t> data(size);
    file.seekg(0);
    file.read(reinterpret_cast<char*>(data.data()), size);

    return data;
}

// Write binary file
void write_binary_file(const std::string& filename, const uint8_t* data, size_t len) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot write to file: " + filename);
    }
    file.write(reinterpret_cast<const char*>(data), len);
}

} // namespace encoding
