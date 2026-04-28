#!/usr/bin/env bash
# compare_cosign.sh — time `cosign sign-blob --key` for the same payload
# sizes that the Criterion bench uses. Run on Linux (or WSL2).
#
# Requires: cosign 3.x, openssl (key gen), dd, date
# Run:   bash scripts/bench/compare_cosign.sh
#
# IMPORTANT: cosign is a Go subprocess — each invocation pays ~50ms
# startup overhead regardless of payload size. The Criterion bench
# measures pure in-process time (no subprocess). The delta between the
# two numbers is the cost of shelling out.

set -euo pipefail

require() { command -v "$1" >/dev/null 2>&1 || { echo "error: $1 not found"; exit 1; }; }
require cosign
require openssl
require dd

RUNS=10
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Generate a throwaway ECDSA P-256 key pair for signing.
KEY="$TMPDIR/bench.key"
openssl ecparam -name prime256v1 -genkey -noout -out "$KEY" 2>/dev/null

run_cosign_sign() {
    local label=$1 size_bytes=$2
    local payload="$TMPDIR/payload.bin"
    local total_ns=0

    dd if=/dev/urandom bs="$size_bytes" count=1 2>/dev/null > "$payload"

    for _ in $(seq 1 $RUNS); do
        local start end
        start=$(date +%s%N)
        cosign sign-blob \
            --key "$KEY" \
            --output-signature /dev/null \
            --yes \
            "$payload" 2>/dev/null
        end=$(date +%s%N)
        total_ns=$(( total_ns + end - start ))
    done

    local mean_us=$(( total_ns / RUNS / 1000 ))
    printf "cosign sign-blob  %-6s  %8d µs  (mean over %d runs, includes ~50ms startup)\n" \
        "$label" "$mean_us" "$RUNS"
}

echo "cosign comparison ($(cosign version 2>&1 | grep -i 'gitversion\|version' | head -1))"
echo "-------------------------------------------------------------------"
run_cosign_sign "1KB"   1024
run_cosign_sign "64KB"  65536
run_cosign_sign "1MB"   1048576
echo ""
echo "Compare against: cargo bench -p swe_justsign_sign --bench sign_verify"
echo "Note: Criterion reports in-process µs; cosign numbers include Go binary startup."
