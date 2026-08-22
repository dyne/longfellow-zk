#pragma once
#if defined(__GNUC__) || defined(__clang__)
#define LONGFELLOW_ZK_API __attribute__((visibility("default")))
#else
#define LONGFELLOW_ZK_API
#endif
