#ifndef HASHCHECK_MD5_H
#define HASHCHECK_MD5_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[4];
    uint64_t bitlen;
    unsigned char buffer[64];
    size_t buffer_len;
} md5_ctx;

void md5_init(md5_ctx *ctx);
void md5_update(md5_ctx *ctx, const unsigned char *data, size_t len);
void md5_final(md5_ctx *ctx, unsigned char out[16]);
void md5_hex(const unsigned char *data, size_t len, char hex_out[33]);

#endif
