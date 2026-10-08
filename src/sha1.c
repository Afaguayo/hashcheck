/*
 * Minimal, self-contained SHA-1 implementation (FIPS 180-4). Bundled so
 * hashcheck can illustrate why SHA-1 is also a poor fit for password
 * storage (fast, unsalted by itself) -- standard algorithm, no other use.
 */
#include "sha1.h"
#include <string.h>
#include <stdio.h>

#define ROTL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_process_block(sha1_ctx *ctx, const unsigned char block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2];
    uint32_t d = ctx->state[3], e = ctx->state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }

        uint32_t temp = ROTL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROTL(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
    ctx->state[3] += d; ctx->state[4] += e;
}

void sha1_init(sha1_ctx *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void sha1_update(sha1_ctx *ctx, const unsigned char *data, size_t len) {
    ctx->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - ctx->buffer_len;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;
        if (ctx->buffer_len == 64) {
            sha1_process_block(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void sha1_final(sha1_ctx *ctx, unsigned char out[20]) {
    uint64_t bitlen = ctx->bitlen;
    unsigned char pad = 0x80;
    sha1_update(ctx, &pad, 1);

    unsigned char zero = 0x00;
    while (ctx->buffer_len != 56) {
        sha1_update(ctx, &zero, 1);
    }

    unsigned char lenbytes[8];
    for (int i = 0; i < 8; i++) {
        lenbytes[i] = (unsigned char)(bitlen >> (56 - 8 * i));
    }
    memcpy(ctx->buffer + ctx->buffer_len, lenbytes, 8);
    sha1_process_block(ctx, ctx->buffer);

    for (int i = 0; i < 5; i++) {
        out[i*4]   = (unsigned char)(ctx->state[i] >> 24);
        out[i*4+1] = (unsigned char)(ctx->state[i] >> 16);
        out[i*4+2] = (unsigned char)(ctx->state[i] >> 8);
        out[i*4+3] = (unsigned char)(ctx->state[i]);
    }
}

void sha1_hex(const unsigned char *data, size_t len, char hex_out[41]) {
    sha1_ctx ctx;
    unsigned char digest[20];
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
    for (int i = 0; i < 20; i++) {
        sprintf(hex_out + i * 2, "%02x", digest[i]);
    }
    hex_out[40] = '\0';
}
