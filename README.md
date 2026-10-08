# hashcheck

[![CI](https://github.com/Afaguayo/hashcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Afaguayo/hashcheck/actions/workflows/ci.yml)
[![C99](https://img.shields.io/badge/C-99-blue)](https://en.wikipedia.org/wiki/C99)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small, portable C99 **password hash-strength auditor**. Given a hash and
an algorithm, it tells you whether that hash is one of ~100 extremely
common weak passwords, and explains *why* the algorithm you used matters.

## What this is (and isn't)

**Is:** a teaching/auditing tool. Point it at a hash you already have
permission to check (e.g. verifying your own test fixtures don't use
`password123`, or a classroom demo of why MD5/SHA-1 are bad password
hashes) and it tells you if it's trivially weak.

**Is not:** a general-purpose cracking tool. There is no brute-force loop,
no mask attack, no arbitrary wordlist support, and no mechanism for
feeding it an unbounded list of guesses. The bundled list is fixed at
~100 of the most common breached passwords on earth — the kind every
password-strength checklist already warns about.

## How it works

- `src/md5.c`, `src/sha1.c`, `src/sha256.c` are minimal, self-contained,
  standards-compliant implementations (RFC 1321, FIPS 180-4) with zero
  external dependencies — written so the whole tool builds with nothing
  but a C99 compiler, no OpenSSL required.
- `data/weak-passwords.txt` (mirrored into `src/weaklist.c` as a static
  array) holds the bundled weak-password list.
- Given `--hash` and `--algo`, `hashcheck` hashes every bundled password
  with that algorithm and compares (case-insensitively) to your input. A
  match means "this is a textbook-weak password"; no match only means
  it's not *one of these ~100* — it says nothing else about strength.
- Either way, it prints a short note on why that specific algorithm is or
  isn't appropriate for password storage at all.

## Build

Requires a C99 compiler (clang or gcc) and `make`.

```bash
make
```

## Usage

```bash
./hashcheck --hash <hex> --algo <md5|sha1|sha256>
```

Example — checking the SHA-256 of the word "password":

```bash
./hashcheck --hash $(printf 'password' | shasum -a 256 | awk '{print $1}') --algo sha256
```

```
hashcheck report
================
Algorithm: sha256
Hash:      5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Result:    MATCH - this hash is the sha256 of the common weak password "password".
           This password is in widely-circulated breach wordlists and should
           never be used.

Algorithm notes:
  SHA-256 is cryptographically sound but still a *fast* general-purpose hash.
  For password storage you want a deliberately slow, memory-hard function
  instead: bcrypt, scrypt, or argon2 (argon2id preferred).
```

### Flags

| Flag | Meaning |
|---|---|
| `--hash <hex>` | The hash to check (required) |
| `--algo <md5\|sha1\|sha256>` | Algorithm the hash was produced with (required) |
| `--list` | Print the bundled weak-password list and exit |
| `--help` | Show usage |

Exit codes: `0` match found, `3` no match, `1` usage error.

## Tests

```bash
make test
```

`tests/run_tests.sh` builds the binary, then cross-checks the bundled
MD5/SHA-1/SHA-256 implementations against the system's own `md5`/`shasum`
tools (so correctness isn't just asserted against hand-typed hex
constants), and exercises the CLI's match/no-match/usage-error paths —
16 assertions in total.

## Limitations

- The weak-password list is intentionally small and fixed; this is a
  triage/teaching tool, not a security boundary.
- No salt handling — real password hashes are (almost) never bare
  MD5/SHA-1/SHA-256 of the plaintext; they're salted and usually run
  through a slow KDF. This tool demonstrates *why* that matters rather
  than attacking real-world salted hashes.

## License

MIT — see [LICENSE](LICENSE).
