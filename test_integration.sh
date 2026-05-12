#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SNIFFER="$SCRIPT_DIR/bin/sniffer"
BPF_OBJ="$SCRIPT_DIR/bpf/sniffer.bpf.o"

echo "=== uprobe-tls-sniffer Integration Test ==="

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "[!] This test must be run as root."
    exit 1
fi

# Check BPF object
if [[ ! -f "$SCRIPT_DIR/bpf/sniffer.bpf.o" ]]; then
    echo "[!] BPF object not found. Run 'make bpf' first."
    exit 1
fi

# Check sniffer binary
if [[ ! -f "$SNIFFER" ]]; then
    echo "[!] sniffer binary not found. Run 'make build' first."
    exit 1
fi

# Start a background curl process that makes HTTPS requests
echo "[*] Starting background curl process..."
(sleep 2; while true; do curl -s https://www.example.com > /dev/null; sleep 2; done) &
CURL_PID=$!
trap "kill $CURL_PID 2>/dev/null; wait $CURL_PID 2>/dev/null" EXIT

sleep 2

echo "[*] Attaching sniffer to curl (PID=$CURL_PID)..."

# Run sniffer for 10 seconds, capture output
timeout 15 "$SNIFFER" --pid "$CURL_PID" 2>&1 | tee /tmp/sniffer_test_output.txt &
SNIFFER_PID=$!
trap "kill $CURL_PID $SNIFFER_PID 2>/dev/null; wait $CURL_PID $SNIFFER_PID 2>/dev/null" EXIT

# Wait for events
sleep 10

kill $SNIFFER_PID 2>/dev/null || true
wait $SNIFFER_PID 2>/dev/null || true

# Verify output contains expected patterns
echo ""
echo "=== Test Results ==="
if grep -q "TLS SEND\|TLS RECV" /tmp/sniffer_test_output.txt; then
    echo "[PASS] TLS events were captured."
else
    echo "[FAIL] No TLS events captured."
    echo "--- Output ---"
    cat /tmp/sniffer_test_output.txt
    exit 1
fi

if grep -qi "example.com" /tmp/sniffer_test_output.txt || grep -qi "HTTP" /tmp/sniffer_test_output.txt; then
    echo "[PASS] Captured data contains HTTP content."
else
    echo "[WARN] Captured data did not contain expected HTTP content (may depend on timing)."
fi

echo "[*] Integration test completed."
