// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#ifndef PRIVACY_PROOFS_ZK_LIB_BLINDZAP_NONCE_STORE_H_
#define PRIVACY_PROOFS_ZK_LIB_BLINDZAP_NONCE_STORE_H_

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace proofs {

constexpr size_t kBlindzapMaxNonceStoreBytes = size_t{16} * 1024 * 1024;

inline bool BlindzapWriteAll(int descriptor, const uint8_t* bytes, size_t size) {
  while (size != 0) {
    const ssize_t written = write(descriptor, bytes, size);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return false;
    bytes += written;
    size -= static_cast<size_t>(written);
  }
  return true;
}

inline std::string BlindzapNonceHex(const std::array<uint8_t, 32>& nonce) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(nonce.size() * 2);
  for (uint8_t byte : nonce) {
    output.push_back(kHex[byte >> 4]);
    output.push_back(kHex[byte & 15]);
  }
  return output;
}

inline bool BlindzapFsyncParentDirectory(const std::string& path) {
  const size_t separator = path.find_last_of('/');
  const std::string directory = separator == std::string::npos
                                    ? "."
                                    : separator == 0 ? "/" : path.substr(0, separator);
  const int descriptor =
      open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (descriptor < 0) return false;
  const bool result = fsync(descriptor) == 0;
  (void)close(descriptor);
  return result;
}

// Atomically reject an existing nonce or append a new one. The store must be a
// regular file owned by the effective user with no group/other permissions.
inline bool BlindzapConsumeNonceFile(const std::string& path,
                                     const std::array<uint8_t, 32>& nonce) {
  const int descriptor = open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC |
                                                O_NOFOLLOW, 0600);
  if (descriptor < 0) return false;
  struct stat metadata {};
  if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_uid != geteuid() || (metadata.st_mode & 077) != 0 ||
      flock(descriptor, LOCK_EX) != 0) {
    (void)close(descriptor);
    return false;
  }

  bool result = false;
  const std::string needle = BlindzapNonceHex(nonce);
  std::string contents;
  std::array<char, 4096> buffer{};
  if (lseek(descriptor, 0, SEEK_SET) >= 0) {
    while (contents.size() <= kBlindzapMaxNonceStoreBytes) {
      const ssize_t count = read(descriptor, buffer.data(), buffer.size());
      if (count < 0 && errno == EINTR) continue;
      if (count < 0) break;
      if (count == 0) {
        bool seen = false;
        size_t begin = 0;
        while (begin < contents.size()) {
          const size_t end = contents.find('\n', begin);
          if (contents.substr(begin, end - begin) == needle) seen = true;
          if (end == std::string::npos) break;
          begin = end + 1;
        }
        if (!seen && lseek(descriptor, 0, SEEK_END) >= 0) {
          const std::string record = needle + "\n";
          result = BlindzapWriteAll(
                       descriptor,
                       reinterpret_cast<const uint8_t*>(record.data()),
                       record.size()) &&
                   fsync(descriptor) == 0 &&
                   BlindzapFsyncParentDirectory(path);
        }
        break;
      }
      if (static_cast<size_t>(count) >
          kBlindzapMaxNonceStoreBytes -
              std::min(contents.size(), kBlindzapMaxNonceStoreBytes)) break;
      contents.append(buffer.data(), static_cast<size_t>(count));
    }
  }
  (void)flock(descriptor, LOCK_UN);
  (void)close(descriptor);
  return result;
}

}  // namespace proofs
#endif
