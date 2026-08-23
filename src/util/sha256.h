#ifndef SHA2_H
#define SHA2_H
#include "util/export.h"

#include <stddef.h>
#include <stdint.h>

/* The incremental API allows hashing of individual input blocks; these blocks
    must be exactly 64 bytes each.
    Use the 'finalize' functions for any remaining bytes (possibly over 64). */

/* Structure for the incremental API */
typedef struct {
    uint8_t *ctx;
} sha256ctx;

/* ====== SHA256 API ==== */

/**
 * Initialize the incremental hashing API
 */
LONGFELLOW_ZK_API void sha256_inc_init(sha256ctx *state);

/**
 * Copy the hashing state
 */
LONGFELLOW_ZK_API void sha256_inc_ctx_clone(sha256ctx *stateout, const sha256ctx *statein);

/**
 * Absorb blocks
 */
LONGFELLOW_ZK_API void sha256_inc_blocks(sha256ctx *state, const uint8_t *in, size_t inblocks);

/**
 * Finalize and obtain the digest
 *
 * If applicable, this function will free the memory associated with the sha256ctx.
 */
LONGFELLOW_ZK_API void sha256_inc_finalize(uint8_t *out, sha256ctx *state, const uint8_t *in, size_t inlen);

/**
 * Destroy the state. Make sure to use this, as this API may not always be stack-based.
 */
LONGFELLOW_ZK_API void sha256_inc_ctx_release(sha256ctx *state);

/**
 * All-in-one sha256 function
 */
LONGFELLOW_ZK_API void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

#endif
