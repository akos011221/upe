# upe - Userspace Packet Engine

Implements Kernel bypass and pulls the raw packets into the Userspace directly.
This way, the application (not the OS) decides what to do with the packet.

Linux only.

## How it works

NIC -> RX Thread -> SPSC Rings -> Worker Threads -> TX (AF_PACKET)

- RX thread captures packets from a live interface (AF_PACKET) or a pcap file
- Software RSS hashes the 5-tuple, distributes the packets to the lock-free SPSC rings
- Worker threads pop packets in bursts, matches against rules, then based on that forward or drop
- TX batches outgoing frames
- Stats thread responsible for the observability, it aggregates per-rule counters and latency histograms every 1s

For details on the design decisions, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Features

- Lock-free packet buffer pool (CAS-based, thread-local caching)
- SPSC ring buffers between RX and workers
- IPv4 & IPv6 support
- Rule matching from INI config file
- ARP & NDP learning
- TTL/hop-limit decrement with cheecksum recalculation
- Per-packet latency measurement via rdtsc
- CPU affinity pinning
- 2MB huge page support (if available)

## Prerequisites

- Linux (tested on Ubuntu 24.04.3 LTS)
- CMake (>= 3.16)
- C11-compatible GCC or Clang
- libpcap
- Root privileges

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Debug build
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Usage

Capture from a live interface:

```bash
sudo ./build/upe --iface eth0 --rules rules.example --verbose 1
```

Read from a pcap file:

```bash
sudo ./build/upe --pcap dump.pcap --rules rules.example
```

## CLI flags

| Flag             | Description                                      |
|------------------|--------------------------------------------------|
| --iface <name>   | Network interface to capture from                |
| --pcap <file>    | Read packets from a pcap file                    |
| --rules <file>   | Rule config file (INI format)                    |
| --verbose <0..2> | 0 = warnings only, 1 = info (default), 2 = debug |
| --duration <sec> | Stop after N seconds (0 = run until Ctrl-C)      |

## Tests

Unit tests:

```bash
./build/test_suite
```

End-to-end smoke test:

```bash
sudo tests/smoke-test.sh
```

Throughput benchmark:

```bash
./build/benchmark_throughput --workers 2 --json -o out.json
```

Packet buffer pool benchmark:

```bash
./build/benchmark_pktbuf --threads 2 --warmup
```