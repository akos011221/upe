# upe - Userspace Packet Engine

Implements Kernel bypass and pulls the raw packets into the Userspace directly. 
This way, the application (not the OS) decides what to do with the packet.

# Architecture

- **RX (Receiver):** Captures raw Ethernet frames using `libpcap`. Allocates a fixed-size buffer from global **Packet Pool**, copies the data into it and pushes the pointer a worker's ring.
- **SPSC Ring:** Lockless Single-Producer & Single-Consumer queues which connects the RX thread to the Worker threads.
- **Flow Matching:**: Workers do the parsing of the raw frames into 5-tuple (srcip, dstip, sport, dport, protocol) flows and looks up the **Rule Table** to find matching entry. It can then decide whether to drop or forward the packet.
**TX (Transmitter):** If packet should be forwarded, then the worker writes the raw packet back to the interface using `AF_PACKET` sockets.

## Usage

```bash
sudo ./upe --iface wlp1s0 --verbose 1
```