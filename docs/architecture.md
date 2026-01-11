# 1. High-level Architecture

UPE is a userspace packet processing engine targeting the shared-nothing architecture. This creates three main planes in the system:

- RX plane for ingress: Captures packets from the NIC and distributes them.
- Worker plane for processing: Parallel threads for parsing the packets and acting on them.
- Control and observability plane: Manages the lifecycle, configuration and  statistics aggregation.

Data Flow

```
[NIC] -> [libpcap] -> [RX Thread]
                          |
                          v
                     (Copy to pktbuf)
                          |
                  [SPSC Ring Round Robin LB]
                  /       |        \
           [Ring 0]    [Ring 1]    [Ring N]
              |           |           |
              v           v           v
         [Worker 0]  [Worker 1]  [Worker N]
             |            |           |
        (Parse/ACL)  (Parse/ACL) (Parse/ACL)
             |            |           |
             v            v           v
          [Action]     [Action]    [Action]
          (Drop/TX)    (Drop/TX)   (Drop/TX)
