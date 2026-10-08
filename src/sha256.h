#ifndef HASHCHECK_SHA256_H
#define HASHCHECK_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    unsigned char buffer[64];
    size_t buffer_len;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len);
/* Writes 32 raw digest bytes to `out`. */
void sha256_final(sha256_ctx *ctx, unsigned char out[32]);

/* Convenience: hash `len` bytes of `data`, write lowercase hex (65 bytes incl. NUL) to `hex_out`. */
void sha256_hex(const unsigned char *data, size_t len, char hex_out[65]);

#endif
