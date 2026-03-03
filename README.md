upe(7)                             Userspace Tools                             upe(7)

NAME
       upe - Userspace Packet Engine (kernel-bypass packet processing)

SYNOPSIS
       upe --iface <name> --rules <file> [--verbose <0..2>] [--duration <sec>]

       upe --pcap <file> --rules <file> [--verbose <0..2>] [--duration <sec>]

DESCRIPTION
       upe is a Linux-only userspace packet processing engine.

       It pulls raw packets directly into userspace using AF_PACKET and
       implements a software pipeline where the application — not the OS
       network stack — decides how packets are handled.

       Designed for:
           * low-latency packet processing
           * lock-free multi-threaded pipelines
           * controlled forwarding and filtering
           * observability and benchmarking

ARCHITECTURE
       High-level data path:

           NIC
             |
             v
           RX Thread
             |
             v
           SPSC Rings (lock-free)
             |
             v
           Worker Threads
             |
             v
           TX (AF_PACKET)

       Pipeline stages:

       RX Thread
              Captures packets from:
                  * Live interface (AF_PACKET)
                  * PCAP file

              Applies software RSS (5-tuple hash) and distributes packets
              across worker threads via SPSC rings.

       Worker Threads
              * Burst-pop packets from rings
              * Match packets against rules (INI-based)
              * Forward or drop based on rule result
              * Decrement TTL / Hop-Limit and recalculate checksum

       TX Path
              * Batches outgoing frames
              * Sends via AF_PACKET

       Stats Thread
              * Aggregates per-rule counters
              * Maintains latency histograms
              * Updates every 1 second

       Detailed design documentation:
              docs/ARCHITECTURE.md

FEATURES
       * Lock-free packet buffer pool (CAS-based, thread-local caching)
       * Lock-free SPSC ring buffers (RX -> workers)
       * IPv4 and IPv6 support
       * INI-based rule matching
       * ARP and NDP learning
       * TTL / Hop-Limit decrement with checksum recalculation
       * Per-packet latency measurement (rdtsc)
       * CPU affinity pinning
       * 2MB huge page support (when available)

REQUIREMENTS
       * Linux (tested on Ubuntu 24.04.3 LTS)
       * CMake >= 3.16
       * C11-compatible GCC or Clang
       * libpcap
       * Root privileges

BUILD
       Release build:

           cmake -B build -DCMAKE_BUILD_TYPE=Release
           cmake --build build

       Debug build:

           cmake -B build -DCMAKE_BUILD_TYPE=Debug
           cmake --build build

USAGE
       Capture from live interface:

           sudo ./build/upe --iface eth0 --rules rules.example --verbose 1

       Read from PCAP file:

           sudo ./build/upe --pcap dump.pcap --rules rules.example

OPTIONS
       --iface <name>
              Network interface to capture from.

       --pcap <file>
              Read packets from a PCAP file.

       --rules <file>
              Rule configuration file (INI format).

       --verbose <0..2>
              Logging verbosity:
                  0  warnings only
                  1  info (default)
                  2  debug

       --duration <sec>
              Stop after N seconds.
              0 means run until interrupted (Ctrl-C).

TESTING
       Unit tests:

           ./build/test_suite

       End-to-end smoke test:

           sudo tests/smoke-test.sh

BENCHMARKS
       Throughput benchmark:

           ./build/benchmark_throughput --workers 2 --json -o out.json

       Packet buffer pool benchmark:

           ./build/benchmark_pktbuf --threads 2 --warmup

NOTES
       * Root privileges are required for raw socket access.
       * Designed for experimentation with userspace networking pipelines.
       * Linux-only.