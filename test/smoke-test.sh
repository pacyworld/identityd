#!/bin/sh
# smoke-test.sh — End-to-end integration test for identityd prototype.
# Starts the daemon, exercises all protocol operations via idctl, validates results.
#
# Usage: sh test/smoke-test.sh [path-to-identityd] [path-to-idctl]
#
# Exit codes: 0 = all passed, 1 = failure

set -e

IDENTITYD="${1:-./zig-out/bin/identityd}"
IDCTL="${2:-./zig-out/bin/idctl}"

TMPDIR=$(mktemp -d)
SOCKET="$TMPDIR/identityd.sock"
DB="$TMPDIR/db"
PIDFILE="$TMPDIR/identityd.pid"
PASS=0
FAIL=0

cleanup() {
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        wait "$(cat "$PIDFILE")" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# Helpers
pass() {
    PASS=$((PASS + 1))
    printf "  \033[32mPASS\033[0m %s\n" "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    printf "  \033[31mFAIL\033[0m %s: %s\n" "$1" "$2"
}

assert_eq() {
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1" "expected '$3', got '$2'"
    fi
}

assert_contains() {
    if echo "$2" | grep -qF "$3"; then
        pass "$1"
    else
        fail "$1" "output does not contain '$3'"
    fi
}

assert_exit_zero() {
    if [ "$2" -eq 0 ]; then
        pass "$1"
    else
        fail "$1" "exit code $2 (expected 0)"
    fi
}

assert_exit_nonzero() {
    if [ "$2" -ne 0 ]; then
        pass "$1"
    else
        fail "$1" "exit code 0 (expected non-zero)"
    fi
}

idctl() {
    "$IDCTL" --socket "$SOCKET" "$@"
}

# ============================================================================
# Start daemon
# ============================================================================

printf "Starting identityd...\n"
mkdir -p "$DB"
"$IDENTITYD" --db "$DB" --socket "$SOCKET" &
echo $! > "$PIDFILE"

# Wait for socket to appear
for i in 1 2 3 4 5 6 7 8 9 10; do
    if [ -S "$SOCKET" ]; then
        break
    fi
    sleep 0.1
done

if [ ! -S "$SOCKET" ]; then
    echo "ERROR: identityd did not start (socket not created)"
    exit 1
fi
printf "identityd running (pid %s, socket %s)\n\n" "$(cat "$PIDFILE")" "$SOCKET"

# ============================================================================
# Identity operations
# ============================================================================

printf "=== Identity Operations ===\n"

# Create identity
OUT=$(idctl adduser alice "Alice Johnson" --email alice@example.com 2>&1) || true
assert_contains "create identity" "$OUT" "created identity: alice"

# Create duplicate should fail
OUT=$(idctl adduser alice "Alice Dup" 2>&1) || true
RC=$?
assert_contains "create identity duplicate" "$OUT" "already exists"

# Get identity
OUT=$(idctl getuser alice 2>&1) || true
assert_contains "get identity id" "$OUT" "id:           alice"
assert_contains "get identity display_name" "$OUT" "display_name: Alice Johnson"
assert_contains "get identity email" "$OUT" "email:        alice@example.com"

# Get non-existent identity
OUT=$(idctl getuser nonexistent 2>&1) || true
assert_contains "get identity not found" "$OUT" "not found"

# Create second identity (no email)
OUT=$(idctl adduser bob "Bob Smith" 2>&1) || true
assert_contains "create identity no email" "$OUT" "created identity: bob"

# Delete identity
OUT=$(idctl deluser bob 2>&1) || true
assert_contains "delete identity" "$OUT" "deleted identity: bob"

# Delete non-existent
OUT=$(idctl deluser bob 2>&1) || true
assert_contains "delete identity not found" "$OUT" "not found"

# ============================================================================
# Group operations
# ============================================================================

printf "\n=== Group Operations ===\n"

# Create group
OUT=$(idctl addgroup eng "Engineering" --description "Engineering department" --type group 2>&1) || true
assert_contains "create group" "$OUT" "created group: eng"

# Create role
OUT=$(idctl addgroup admin-role "Administrator" --type role 2>&1) || true
assert_contains "create role" "$OUT" "created group: admin-role"

# Create duplicate group
OUT=$(idctl addgroup eng "Eng Again" 2>&1) || true
assert_contains "create group duplicate" "$OUT" "already exists"

# Delete group
OUT=$(idctl delgroup admin-role 2>&1) || true
assert_contains "delete group" "$OUT" "deleted group: admin-role"

# Delete non-existent group
OUT=$(idctl delgroup admin-role 2>&1) || true
assert_contains "delete group not found" "$OUT" "not found"

# ============================================================================
# Edge operations
# ============================================================================

printf "\n=== Edge Operations ===\n"

# Create some entities for edge testing
idctl adduser charlie "Charlie" 2>&1 >/dev/null || true
idctl adduser diana "Diana" 2>&1 >/dev/null || true
idctl addgroup devteam "Dev Team" 2>&1 >/dev/null || true

# Add edge
OUT=$(idctl addedge alice member_of eng --data '{"role":"lead"}' 2>&1) || true
assert_contains "add edge" "$OUT" "added edge: alice --[member_of]--> eng"

# Add more edges for graph testing
idctl addedge charlie member_of devteam 2>&1 >/dev/null || true
idctl addedge diana member_of devteam 2>&1 >/dev/null || true
idctl addedge devteam part_of eng 2>&1 >/dev/null || true

# Has edge (true)
OUT=$(idctl hasedge alice member_of eng 2>&1) || true
assert_eq "has edge (exists)" "$OUT" "true"

# Has edge (false)
OUT=$(idctl hasedge alice member_of devteam 2>&1) || true
assert_eq "has edge (not exists)" "$OUT" "false"

# Remove edge
OUT=$(idctl deledge alice member_of eng 2>&1) || true
assert_contains "remove edge" "$OUT" "removed edge"

# Has edge after removal
OUT=$(idctl hasedge alice member_of eng 2>&1) || true
assert_eq "has edge after removal" "$OUT" "false"

# ============================================================================
# Graph query operations
# ============================================================================

printf "\n=== Graph Queries ===\n"

# Re-add edge for path testing
idctl addedge alice member_of eng 2>&1 >/dev/null || true

# Has path (direct — depth 1)
OUT=$(idctl haspath alice eng member_of --depth 1 2>&1) || true
assert_eq "has path direct" "$OUT" "true"

# Has path (transitive: charlie → devteam → eng via different edge types won't work)
# charlie --[member_of]--> devteam --[part_of]--> eng
# haspath uses single edge type, so charlie can't reach eng via member_of alone
OUT=$(idctl haspath charlie eng member_of --depth 3 2>&1) || true
assert_eq "has path single-type (no transitive)" "$OUT" "false"

# Has path using part_of: devteam → eng
OUT=$(idctl haspath devteam eng part_of --depth 2 2>&1) || true
assert_eq "has path part_of" "$OUT" "true"

# Has path (non-existent)
OUT=$(idctl haspath alice diana member_of --depth 5 2>&1) || true
assert_eq "has path (no path)" "$OUT" "false"

# ============================================================================
# Shutdown + verify clean exit
# ============================================================================

printf "\n=== Shutdown ===\n"

kill "$(cat "$PIDFILE")" 2>/dev/null
# Daemon calls _exit(0) from signal handler (prototype limitation —
# Zig's accept() can't be cleanly interrupted). Brief wait for exit.
sleep 0.2
if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    pass "daemon exited on SIGTERM"
else
    fail "daemon exited on SIGTERM" "process still running"
    kill -9 "$(cat "$PIDFILE")" 2>/dev/null || true
fi
rm -f "$PIDFILE"

# ============================================================================
# Summary
# ============================================================================

printf "\n"
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    printf "\033[32m✓ All %d tests passed\033[0m\n" "$TOTAL"
    exit 0
else
    printf "\033[31m✗ %d/%d tests failed\033[0m\n" "$FAIL" "$TOTAL"
    exit 1
fi
