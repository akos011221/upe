### Userspace Packet Engine (UPE)

The repository contains two different packet processing engines.

#### 1. Standard Linux Engine

Runs on any Linux system without special hardware. Uses kernel sockets for I/O.

- **RX:** libpcap reading from interface or PCAP file
- **TX:** Raw AF_PACKET socket with batching
- **Pipeline:** One RX thread distributes packets to N worker threads via lock-free SPSC rings
- **Workers:** Process packets (L3 forwarding, filtering, etc.) and send via TX socket
- **Memory:** Custom packet pool with 2MB huge pages
- **Stats:** Separate thread dumps rule counters, latency histograms, and neighbor tables

**Docs:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

#### 2. DPDK Router Engine

Full kernel bypass. Runs on physical NICs with DPDK PMD drivers.

In progress...

---
