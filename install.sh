#!/usr/bin/env bash
# install.sh — build ZERO-ORBIT components
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Creating directories..."
mkdir -p config rules reports backups modules patches

echo "[*] Building Go orbit..."
go build -o orbit orbit.go

echo "[*] Building C++ engine..."
g++ -O2 -std=c++17 -o engine engine.cpp

echo "[*] Building Rust shield..."
rustc -O -o shield shield.rs

echo "[*] Making zero_orbit.py executable..."
chmod +x zero_orbit.py
ln -sf "$(pwd)/zero_orbit.py" /usr/local/bin/zero-orbit 2>/dev/null || true

echo "[*] Seeding config/scope.txt ..."
if [ ! -f config/scope.txt ]; then
cat > config/scope.txt <<'EOF'
# ZERO-ORBIT scope file — authorized targets only.
# Add entries like:
# example.com
# *.example.com
EOF
fi

echo "[+] Done. Run:  zero-orbit"