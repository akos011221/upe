# upe - Userspace Packet Engine

Implements Kernel bypass and pulls the raw packets into the Userspace directly. 
This way, the application (not the OS) decides what to do with the packet.

## Architecture

For details on the design decisions, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Usage

```bash
sudo ./upe --iface wlp1s0 --verbose 1
```
