/*
 * Minimal, self-contained MD5 implementation (RFC 1321), bundled only so
 * hashcheck can demonstrate *why* MD5 is considered weak for password
 * storage (fast, no built-in salting/iteration) -- not for any other use.
 */
#include "md5.h"
#include <string.h>
#include <stdio.h>

static const uint32_t K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const int S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

#define LEFTROTATE(x,c) (((x) << (c)) | ((x) >> (32 - (c))))

static void md5_process_block(md5_ctx *ctx, const unsigned char block[64]) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];

    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3*i + 5) % 16; }
        else { f = c ^ (b | ~d); g = (7*i) % 16; }

        uint32_t temp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE(a + f + K[i] + m[g], S[i]);
        a = temp;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
}

void md5_init(md5_ctx *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void md5_update(md5_ctx *ctx, const unsigned char *data, size_t len) {
    ctx->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - ctx->buffer_len;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;
        if (ctx->buffer_len == 64) {
            md5_process_block(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void md5_final(md5_ctx *ctx, unsigned char out[16]) {
    uint64_t bitlen = ctx->bitlen;
    unsigned char pad = 0x80;
    md5_update(ctx, &pad, 1);

    unsigned char zero = 0x00;
    while (ctx->buffer_len != 56) {
        md5_update(ctx, &zero, 1);
    }

    unsigned char lenbytes[8];
    for (int i = 0; i < 8; i++) {
        lenbytes[i] = (unsigned char)(bitlen >> (8 * i)); /* little-endian length for MD5 */
    }
    memcpy(ctx->buffer + ctx->buffer_len, lenbytes, 8);
    md5_process_block(ctx, ctx->buffer);

    for (int i = 0; i < 4; i++) {
        out[i*4]   = (unsigned char)(ctx->state[i]);
        out[i*4+1] = (unsigned char)(ctx->state[i] >> 8);
        out[i*4+2] = (unsigned char)(ctx->state[i] >> 16);
        out[i*4+3] = (unsigned char)(ctx->state[i] >> 24);
    }
}

void md5_hex(const unsigned char *data, size_t len, char hex_out[33]) {
    md5_ctx ctx;
    unsigned char digest[16];
    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(&ctx, digest);
    for (int i = 0; i < 16; i++) {
        sprintf(hex_out + i * 2, "%02x", digest[i]);
    }
    hex_out[32] = '\0';
}
