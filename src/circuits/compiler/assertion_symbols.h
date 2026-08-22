// Copyright 2026 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_COMPILER_ASSERTION_SYMBOLS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_COMPILER_ASSERTION_SYMBOLS_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace proofs {
class AssertionSourceId { public: explicit AssertionSourceId(uint32_t value = 0) : value_(value) {} uint32_t value() const { return value_; } private: uint32_t value_; };

class AssertionSymbolTracker {
 public:
  class Scope { public: Scope(AssertionSymbolTracker* tracker, std::string path) : tracker_(tracker) { tracker_->paths_.push_back(std::move(path)); } Scope(const Scope&) = delete; Scope& operator=(const Scope&) = delete; Scope(Scope&& other) noexcept : tracker_(other.tracker_) { other.tracker_ = nullptr; } ~Scope() { if (tracker_) tracker_->paths_.pop_back(); } private: AssertionSymbolTracker* tracker_; };
  Scope scope(std::string path) { return Scope(this, std::move(path)); }
  AssertionSourceId current() { if (paths_.empty()) return AssertionSourceId(); std::string path; for (const auto& part : paths_) { if (!path.empty()) path += '/'; path += part; } for (size_t i = 0; i < sources_.size(); ++i) if (sources_[i] == path) return AssertionSourceId(static_cast<uint32_t>(i + 1)); sources_.push_back(path); return AssertionSourceId(static_cast<uint32_t>(sources_.size())); }
  const std::string* path(AssertionSourceId id) const { return id.value() == 0 || id.value() > sources_.size() ? nullptr : &sources_[id.value() - 1]; }
 private: std::vector<std::string> paths_; std::vector<std::string> sources_;
};

struct AssertionSymbol { size_t layer; uint32_t wire; std::vector<std::string> paths; };
enum class AssertionSymbolError { kNone, kTruncated, kBadMagic, kBadVersion, kWrongCircuit, kMalformed };

// Optional LFSY companion data. It never participates in circuit/proof bytes.
class AssertionSymbols {
 public:
  static constexpr uint8_t kMagic[4] = {'L', 'F', 'S', 'Y'}; static constexpr uint8_t kVersion = 1;
  std::vector<AssertionSymbol> entries;
  const std::vector<std::string>* paths_for(size_t layer, uint32_t wire) const {
    for (const auto& entry : entries)
      if (entry.layer == layer && entry.wire == wire) return &entry.paths;
    return nullptr;
  }
  std::vector<uint8_t> to_bytes(const uint8_t id[32]) const { std::vector<uint8_t> out(kMagic, kMagic + 4); out.push_back(kVersion); out.insert(out.end(), id, id + 32); put(out, entries.size()); for (const auto& e : entries) { put(out, e.layer); put(out, e.wire); put(out, e.paths.size()); for (const auto& p : e.paths) { put(out, p.size()); out.insert(out.end(), p.begin(), p.end()); } } return out; }
  static AssertionSymbolError from_bytes(const std::vector<uint8_t>& in, const uint8_t id[32], AssertionSymbols* out) {
    if (in.size() < 37) return AssertionSymbolError::kTruncated; for (size_t i = 0; i < 4; ++i) if (in[i] != kMagic[i]) return AssertionSymbolError::kBadMagic; if (in[4] != kVersion) return AssertionSymbolError::kBadVersion; for (size_t i = 0; i < 32; ++i) if (in[5 + i] != id[i]) return AssertionSymbolError::kWrongCircuit;
    size_t pos = 37, count; if (!get(in, &pos, &count) || count > in.size()) return AssertionSymbolError::kMalformed; AssertionSymbols parsed;
    for (size_t n = 0; n < count; ++n) { size_t layer, wire, paths; if (!get(in, &pos, &layer) || !get(in, &pos, &wire) || !get(in, &pos, &paths) || wire > UINT32_MAX) return AssertionSymbolError::kMalformed; AssertionSymbol e{layer, static_cast<uint32_t>(wire), {}}; for (size_t p = 0; p < paths; ++p) { size_t length; if (!get(in, &pos, &length) || length > in.size() - pos) return AssertionSymbolError::kTruncated; e.paths.emplace_back(reinterpret_cast<const char*>(in.data() + pos), length); pos += length; } if (e.paths.empty()) return AssertionSymbolError::kMalformed; parsed.entries.push_back(std::move(e)); }
    if (pos != in.size()) return AssertionSymbolError::kMalformed; *out = std::move(parsed); return AssertionSymbolError::kNone;
  }
 private:
  static void put(std::vector<uint8_t>& out, size_t value) { do { uint8_t byte = static_cast<uint8_t>(value & 0x7f); value >>= 7; out.push_back(value ? static_cast<uint8_t>(byte | 0x80) : byte); } while (value); }
  static bool get(const std::vector<uint8_t>& in, size_t* pos, size_t* value) { *value = 0; unsigned shift = 0; while (*pos < in.size() && shift < sizeof(size_t) * 8) { uint8_t b = in[(*pos)++]; *value |= static_cast<size_t>(b & 0x7f) << shift; if (!(b & 0x80)) return true; shift += 7; } return false; }
};
}  // namespace proofs
#endif
