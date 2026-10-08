#ifndef HASHCHECK_WEAKLIST_H
#define HASHCHECK_WEAKLIST_H

#include <stddef.h>

/* A small, bundled list of extremely common weak passwords, generated
 * from data/weak-passwords.txt. Used only to flag whether a submitted
 * hash matches one of these well-known values -- this is NOT a general
 * wordlist-cracking engine (see README "What this is not"). */
extern const char *WEAK_PASSWORDS[];
extern const size_t WEAK_PASSWORDS_COUNT;

#endif
