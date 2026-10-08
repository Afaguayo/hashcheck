/*
 * hashcheck - a password HASH-STRENGTH AUDITOR, not a general cracking
 * tool.
 *
 * Given a hash and an algorithm name, it:
 *   1. Checks whether the hash matches one of ~100 bundled, extremely
 *      common weak passwords (the kind every real-world breach corpus
 *      is full of), hashed with the chosen algorithm.
 *   2. Prints algorithm-weakness notes so the output is educational even
 *      when there's no match.
 *
 * What this is NOT: there is no brute force loop, no mask attack, no
 * arbitrary-size wordlist support, and no support for targeting hashes
 * you don't have explicit permission to test. See README for the
 * rationale.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "weaklist.h"

typedef enum { ALGO_MD5, ALGO_SHA1, ALGO_SHA256, ALGO_UNKNOWN } algo_t;

static algo_t parse_algo(const char *s) {
    if (strcasecmp(s, "md5") == 0) return ALGO_MD5;
    if (strcasecmp(s, "sha1") == 0 || strcasecmp(s, "sha-1") == 0) return ALGO_SHA1;
    if (strcasecmp(s, "sha256") == 0 || strcasecmp(s, "sha-256") == 0) return ALGO_SHA256;
    return ALGO_UNKNOWN;
}

static void hash_with(algo_t algo, const char *input, char *hex_out, size_t hex_out_size) {
    size_t len = strlen(input);
    switch (algo) {
        case ALGO_MD5:
            if (hex_out_size < 33) abort();
            md5_hex((const unsigned char *)input, len, hex_out);
            break;
        case ALGO_SHA1:
            if (hex_out_size < 41) abort();
            sha1_hex((const unsigned char *)input, len, hex_out);
            break;
        case ALGO_SHA256:
            if (hex_out_size < 65) abort();
            sha256_hex((const unsigned char *)input, len, hex_out);
            break;
        default:
            hex_out[0] = '\0';
    }
}

static void print_weakness_notes(algo_t algo) {
    printf("\nAlgorithm notes:\n");
    switch (algo) {
        case ALGO_MD5:
            printf("  MD5 is cryptographically broken for collision resistance and, worse for\n"
                   "  password storage, extremely fast -- modern GPUs compute billions of MD5\n"
                   "  hashes per second. Never use bare MD5 for passwords.\n");
            break;
        case ALGO_SHA1:
            printf("  SHA-1 is deprecated for security use and, like MD5, is fast enough that a\n"
                   "  GPU can brute-force short/common passwords quickly. Not suitable for\n"
                   "  password storage on its own.\n");
            break;
        case ALGO_SHA256:
            printf("  SHA-256 is cryptographically sound but still a *fast* general-purpose hash.\n"
                   "  For password storage you want a deliberately slow, memory-hard function\n"
                   "  instead: bcrypt, scrypt, or argon2 (argon2id preferred).\n");
            break;
        default:
            break;
    }
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "hashcheck - password hash-strength auditor (not a general cracking tool)\n\n"
        "Usage:\n"
        "  %s --hash <hex> --algo <md5|sha1|sha256>\n\n"
        "Options:\n"
        "  --hash <hex>   The hash to check (hex string)\n"
        "  --algo <name>  One of: md5, sha1, sha256\n"
        "  --list         Print the bundled weak-password list and exit\n"
        "  --help         Show this help\n\n"
        "Exit codes:\n"
        "  0  hash matches a bundled weak password (and notes were printed)\n"
        "  1  usage error\n"
        "  3  hash did not match any bundled weak password\n",
        prog);
}

int main(int argc, char **argv) {
    const char *hash_arg = NULL;
    const char *algo_arg = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hash") == 0 && i + 1 < argc) {
            hash_arg = argv[++i];
        } else if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc) {
            algo_arg = argv[++i];
        } else if (strcmp(argv[i], "--list") == 0) {
            for (size_t j = 0; j < WEAK_PASSWORDS_COUNT; j++) {
                printf("%s\n", WEAK_PASSWORDS[j]);
            }
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!hash_arg || !algo_arg) {
        fprintf(stderr, "Error: --hash and --algo are both required.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    algo_t algo = parse_algo(algo_arg);
    if (algo == ALGO_UNKNOWN) {
        fprintf(stderr, "Error: unknown algorithm '%s' (expected md5, sha1, or sha256)\n", algo_arg);
        return 1;
    }

    char computed[65];
    const char *match = NULL;
    for (size_t j = 0; j < WEAK_PASSWORDS_COUNT; j++) {
        hash_with(algo, WEAK_PASSWORDS[j], computed, sizeof(computed));
        if (strcasecmp(computed, hash_arg) == 0) {
            match = WEAK_PASSWORDS[j];
            break;
        }
    }

    printf("hashcheck report\n================\n");
    printf("Algorithm: %s\n", algo_arg);
    printf("Hash:      %s\n", hash_arg);

    if (match) {
        printf("Result:    MATCH - this hash is the %s of the common weak password \"%s\".\n",
               algo_arg, match);
        printf("           This password is in widely-circulated breach wordlists and should\n"
               "           never be used.\n");
        print_weakness_notes(algo);
        return 0;
    }

    printf("Result:    no match against the bundled %zu-password weak-password list.\n", WEAK_PASSWORDS_COUNT);
    printf("           This does NOT mean the password is strong -- it only means it isn't\n"
           "           one of the ~100 most common ones bundled with this tool.\n");
    print_weakness_notes(algo);
    return 3;
}
