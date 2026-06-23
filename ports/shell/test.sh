#!/usr/bin/env sh
# Smoke test for the shell port. Asserts byte-identical parity with the Python
# reference head. Exit 0 = pass.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AR="$HERE/auditrail.sh"

REFERENCE_HEAD="8ae3d48a5736f485bd64d7d812d5255a5548962684e79a85d05bbbfac1ea94d3"
SAMPLE='[{"ts":"2026-06-08T09:00:00Z","actor":"alice","action":"login"},{"ts":"2026-06-08T09:01:00Z","actor":"alice","action":"read","resource":"r1"},{"ts":"2026-06-08T09:02:00Z","actor":"bob","action":"delete","resource":"r1"}]'

fail() { echo "FAIL: $1" >&2; exit 1; }
pass=0

# 1. head parity with the Python/Go/Rust/JS reference
HEAD=$(printf '%s' "$SAMPLE" | sh "$AR" attest - | awk -F= '/^head=/{print $2}')
[ "$HEAD" = "$REFERENCE_HEAD" ] || fail "head mismatch: got $HEAD"
pass=$((pass+1)); echo "ok - byte-identical head vs reference"

# 2. event count
CNT=$(printf '%s' "$SAMPLE" | sh "$AR" attest - | awk -F= '/^event_count=/{print $2}')
[ "$CNT" = "3" ] || fail "event_count mismatch: $CNT"
pass=$((pass+1)); echo "ok - event count is 3"

# 3. verify intact
printf '%s' "$SAMPLE" | sh "$AR" verify - >/dev/null || fail "verify exited non-zero on intact chain"
pass=$((pass+1)); echo "ok - intact chain verifies (exit 0)"

# 4. JSONL input yields same head
JSONL='{"ts":"2026-06-08T09:00:00Z","actor":"alice","action":"login"}
{"ts":"2026-06-08T09:01:00Z","actor":"alice","action":"read","resource":"r1"}
{"ts":"2026-06-08T09:02:00Z","actor":"bob","action":"delete","resource":"r1"}'
HEAD2=$(printf '%s' "$JSONL" | sh "$AR" attest - | awk -F= '/^head=/{print $2}')
[ "$HEAD2" = "$REFERENCE_HEAD" ] || fail "JSONL head mismatch: $HEAD2"
pass=$((pass+1)); echo "ok - JSONL input matches reference head"

# 5. expected-head mismatch -> exit 2 (tamper signal)
set +e
AUDITRAIL_EXPECT_HEAD="deadbeef" sh -c "printf '%s' '$SAMPLE' | sh '$AR' verify -" >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ] || fail "expected exit 2 on head mismatch, got $rc"
pass=$((pass+1)); echo "ok - expected-head mismatch exits 2"

echo ""
echo "$pass assertions passed"
