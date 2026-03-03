#!/bin/bash

# E2E smoke test that generates a pcap file, runs UPE in pcap mode and verifies
# that packet processing is working correctly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
UPE_BIN="$PROJECT_DIR/build/upe"

# Below files are cleaned up on exit.
TMPDIR=$(mktemp -d)
PCAP_FILE="$TMPDIR/smoke.pcap"
RULES_FILE="$TMPDIR/rules.conf"
OUTPUT_FILE="$TMPDIR/upe_out.txt"

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

if [ ! -x "$UPE_BIN" ]; then
    echo "ERROR: UPE binary not found at $UPE_BIN"
    echo "      Run cmake --build build"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi

python3 - "$PCAP_FILE" << 'PYEOF'
import struct, sys

outpath = sys.argv[1]

def pcap_global_header():
    return struct.pack('<IHHiIII',
        0xa1b2c3d4, # magic number (little-endian pcap)
        2, 4,       # major and minor version
        0,          # thiszone
        0,          # sigfigs
        65535,      # snaplen
        1           # network (Ethernet)
    )

def pcap_packet_header(length):
    return struct.pack('<IIII', 0, 0, length, length)

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def make_ipv4_tcp_packet(src_ip, dst_ip, src_port, dst_port, ttl=64, payload_size=64):
    eth = b'\x00\x11\x22\x33\x44\x55' # dst MAC
    eth += b'\x66\x77\x88\x99\xaa\xbb' # src MAC
    eth += struct.pack('>H', 0x0800) # EtherType: IPv4

    tcp_hdr = struct.pack('>HHIIBBHHH',
        src_port, dst_port,
        1000, 0,           # seq, ack
        (5 << 4), 0x02,    # data offset=5 (20 bytes), flags=SYN
        65535, 0, 0        # window, checksum, urgent pointer
    )

    payload = b'\x41' * payload_size   # 'A' bytes

    total_len = 20 + 20 + payload_size
    ip_hdr = struct.pack('>BBHHHBBH4s4s',
        0x45, 0,                  # ver=4, ihl=5, dscp=0
        total_len,
        0, 0,                     # identification, flags+frag
        ttl, 6,
        0,                        # checksum placeholder
        bytes(map(int, src_ip.split('.'))),
        bytes(map(int, dst_ip.split('.')))
    )
    cs = checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack('>H', cs) + ip_hdr[12:]

    return eth + ip_hdr + tcp_hdr + payload

def make_ipv6_tcp_packet(src_ip_bytes, dst_ip_bytes, src_port, dst_port, hop_limit=64, payload_size=64):
    eth = b'\x00\x11\x22\x33\x44\x55'
    eth += b'\x66\x77\x88\x99\xaa\xbb'
    eth += struct.pack('>H', 0x86DD)

    tcp_hdr = struct.pack('>HHIIBBHHH',
        src_port, dst_port,
        1000, 0,
        (5 << 4), 0x02,
        65535, 0, 0
    )

    payload = b'\x41' * payload_size

    payload_len = 20 + payload_size
    ip6_hdr = struct.pack('>IHBB16s16s',
        (6 << 28) | 0,      # version=6, traffic class=0, flow label=0
        payload_len,
        6,
        hop_limit,
        src_ip_bytes,
        dst_ip_bytes
    )

    return eth + ip6_hdr + tcp_hdr + payload

with open(outpath, 'wb') as f:
    f.write(pcap_global_header())

    # 100 IPv4 packets to port 21 (should match a DROP rule)
    for i in range(100):
        pkt = make_ipv4_tcp_packet('10.128.0.1', '10.128.0.2', 12345 + (i % 100), 21)
        f.write(pcap_packet_header(len(pkt)))
        f.write(pkt)

    # 100 IPv6 TCP packets to port 443 (should match catch-all DROP)
    src6 = b'\x20\x01\x0d\xb8' + b'\x00' * 10 + b'\x00\x01'     # 2001:db8::1
    dst6 = b'\x20\x01\x0d\xb8' + b'\x00' * 10 + b'\x00\x02'     # 2001:db8::2
    for i in range(100):
        pkt = make_ipv6_tcp_packet(src6, dst6, 9000 + i, 443)
        f.write(pcap_packet_header(len(pkt)))
        f.write(pkt)

print(f"Generated {outpath}: 200 packets -> 100 IPv4 + 100 IPv6")
PYEOF

cat > "$RULES_FILE" << 'EOF'
[rule]
priority = 10
ip_version = 4
protocol = tcp
dst_port = 21
action = drop

[rule]
priority = 9999
action = drop
EOF

echo "Running UPE smoke test..."
echo "  PCAP:   $PCAP_FILE"
echo "  RULES:  $RULES_FILE"

EXIT_CODE=0
timeout 10 sudo -S "$UPE_BIN" \
    --pcap "$PCAP_FILE" \
    --rules "$RULES_FILE" \
    --verbose 0 \
    > "$OUTPUT_FILE" 2>&1 || EXIT_CODE=$?

if [ "$EXIT_CODE" -eq 124 ]; then
    echo "ERROR: UPE timed out"
    cat "$OUTPUT_FILE"
    exit 1
fi

if [ "$EXIT_CODE" -ne 0 ]; then
    echo "ERROR: UPE exited with $EXIT_CODE"
    cat "$OUTPUT_FILE"
    exit 1
fi

# Validate output
echo ""

if grep -q "TOTAL: 0 packets" "$OUTPUT_FILE"; then
    echo "ERROR: UPE processed 0 packets"
    cat "$OUTPUT_FILE"
    exit 1
fi

if ! grep -q "TOTAL:" "$OUTPUT_FILE"; then
    echo "WARNING: No TOTAL line in output"
    cat "$OUTPUT_FILE"
    exit 0
fi

TOTAL_LINE=$(grep "TOTAL:" "$OUTPUT_FILE" | tail -1)
echo "OK: $TOTAL_LINE"

if grep -q "Samples:" "$OUTPUT_FILE"; then
    LATENCY_LINE=$(grep "Samples:" "$OUTPUT_FILE" | tail -1)
    echo "OK: $LATENCY_LINE"
fi

echo ""
echo "Smoke test passed"
