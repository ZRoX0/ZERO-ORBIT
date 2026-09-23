#!/usr/bin/env bash
# smoke_test.sh — verify everything is wired correctly
set -euo pipefail
cd "$(dirname "$0")"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
fail() { echo -e "${RED}[FAIL] $1${NC}"; exit 1; }
pass() { echo -e "${GREEN}[PASS] $1${NC}"; }

echo "=== ZERO-ORBIT smoke test ==="

# 1. Files exist
for f in libshield.so libengine.so orbit zero_orbit.py; do
    [ -f "$f" ] || fail "$f missing — run ./build.sh"
done
pass "binaries present"

# 2. Symbols exported
nm -D libshield.so 2>/dev/null | grep -q shield_check_scope \
    || fail "libshield.so missing symbols"
pass "libshield symbols OK"

nm -D libengine.so 2>/dev/null | grep -q engine_parse_headers \
    || fail "libengine.so missing symbols"
pass "libengine symbols OK"

# 3. orbit runs
./orbit validate --target example.com >/dev/null 2>&1 \
    || fail "orbit validate failed"
pass "orbit validate works"

./orbit validate --target 'bad target!' >/dev/null 2>&1 \
    && fail "orbit validate accepted bad target" \
    || pass "orbit rejects invalid target"

# 4. Scope enforcement (must be blocked without scope.txt)
mkdir -p config
cp -n config/scope.txt config/scope.txt.bak 2>/dev/null || true
echo "# empty" > config/scope.txt

if ./orbit scan --target example.com --scope config/scope.txt 2>&1 | grep -q "ACCESS BLOCKED"; then
    pass "scope default-deny works"
else
    fail "scope not enforced!"
fi

# 5. Python CLI parses
python3 -c "import ast; ast.parse(open('zero_orbit.py').read())" \
    || fail "zero_orbit.py has syntax errors"
pass "python CLI parses"

echo
echo -e "${GREEN}=== ALL CHECKS PASSED ===${NC}"