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

def make_ipv4_tcp_packet(src_ip, dst_ip, src_port, dst_port ttl=64, payload_size=64):
    eth = b'\x00\x11\x22\x33\x44\x55' # dst MAC
    eth += b'\x66\x77\x88\x99\xaa\xbb' # src MAC
    eth += struct.pack('>H', 0x0800) # EtherType: IPv4

    tcp_hdr = struct.pack('>HHIIBBHHH',
        src_port, dst_port,
        1000, 0,           # seq, ack
        (5 << 4), 0x02,    # data offset=5 (20 bytes), flags=SYN
        65535, 0, 0        # window, checksum, urgent pointer

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




