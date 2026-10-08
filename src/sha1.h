#ifndef HASHCHECK_SHA1_H
#define HASHCHECK_SHA1_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[5];
    uint64_t bitlen;
    unsigned char buffer[64];
    size_t buffer_len;
} sha1_ctx;

void sha1_init(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, const unsigned char *data, size_t len);
void sha1_final(sha1_ctx *ctx, unsigned char out[20]);
void sha1_hex(const unsigned char *data, size_t len, char hex_out[41]);

#endif
