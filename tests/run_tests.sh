#!/usr/bin/env bash
# Test suite for hashcheck. Cross-checks the bundled MD5/SHA-1/SHA-256
# implementations against the system's own hashing tools (so we don't
# depend on hand-memorized hex constants), then exercises the CLI logic.
set -euo pipefail

cd "$(dirname "$0")/.."
BIN=./hashcheck
PASS=0
FAIL=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "ok   - $desc"
        PASS=$((PASS+1))
    else
        echo "FAIL - $desc (expected [$expected], got [$actual])"
        FAIL=$((FAIL+1))
    fi
}

assert_exit() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "ok   - $desc (exit $actual)"
        PASS=$((PASS+1))
    else
        echo "FAIL - $desc (expected exit $expected, got $actual)"
        FAIL=$((FAIL+1))
    fi
}

system_hash() {
    local algo="$1" input="$2"
    case "$algo" in
        md5) printf '%s' "$input" | (md5sum 2>/dev/null || md5) | awk '{print $1}' ;;
        sha1) printf '%s' "$input" | shasum -a 1 | awk '{print $1}' ;;
        sha256) printf '%s' "$input" | shasum -a 256 | awk '{print $1}' ;;
    esac
}

echo "== CLI behavior (also cross-checks our MD5/SHA-1/SHA-256 against system tools) =="

# "password" is in the bundled weak list -- its real hash must MATCH.
for algo in md5 sha1 sha256; do
    real_hash=$(system_hash "$algo" "password")
    set +e
    out=$($BIN --hash "$real_hash" --algo "$algo")
    code=$?
    set -e
    assert_exit "MATCH exit code for $algo(password)" 0 "$code"
    echo "$out" | grep -q "MATCH" && { echo "ok   - $algo report contains MATCH"; PASS=$((PASS+1)); } || { echo "FAIL - $algo report missing MATCH"; FAIL=$((FAIL+1)); }
done

# A long random string is (almost certainly) NOT in the weak list -- its
# hash must NOT match.
strong="Xk29-qT-zL-9f3h-not-a-common-password-7q2m"
for algo in md5 sha1 sha256; do
    strong_hash=$(system_hash "$algo" "$strong")
    set +e
    out=$($BIN --hash "$strong_hash" --algo "$algo")
    code=$?
    set -e
    assert_exit "no-match exit code for $algo(strong)" 3 "$code"
    echo "$out" | grep -q "no match" && { echo "ok   - $algo report says no match"; PASS=$((PASS+1)); } || { echo "FAIL - $algo report missing 'no match'"; FAIL=$((FAIL+1)); }
done

# --list prints at least one well-known weak password.
$BIN --list | grep -qx "password" && { echo "ok   - --list includes 'password'"; PASS=$((PASS+1)); } || { echo "FAIL - --list missing 'password'"; FAIL=$((FAIL+1)); }
count=$($BIN --list | wc -l | tr -d ' ')
if [ "$count" -ge 50 ]; then
    echo "ok   - --list has >= 50 entries ($count)"
    PASS=$((PASS+1))
else
    echo "FAIL - --list has too few entries ($count)"
    FAIL=$((FAIL+1))
fi

# Usage errors.
set +e
$BIN >/dev/null 2>&1
code=$?
set -e
assert_exit "missing args usage error" 1 "$code"

set +e
$BIN --hash deadbeef --algo notarealalgo >/dev/null 2>&1
code=$?
set -e
assert_exit "unknown algorithm usage error" 1 "$code"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
