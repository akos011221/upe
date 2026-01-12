# UPE Architecture Guide (2026.01.12)

## 1. Memory Management
**File:** `src/pktbuf.c`

### Design
Currently, the system uses a **Single Global Pool** protected by a mutex.

*   **Zero-Allocation (Runtime):** We allocate `4096` buffers (2KB each) at startup using `calloc`. This eliminates `malloc` latency during packet processing.
*   **Global Contention:** A single `pthread_mutex_t g_pool_lock` protects the free list.
    *   **RX Thread** locks it to get a buffer (`pktbuf_alloc`).
    *   **Worker Threads** lock it to return a buffer (`pktbuf_free`).

### API
*   **`pktbuf_pool_init`**: Pre-allocates the entire heap of packets. This ensures the engine never fails due to OOM (Out Of Memory) during operation.
*   **`pktbuf_alloc` / `pktbuf_free`**: These are the synchronization points.
    *   *Current Limitation:* As core count increases, this lock becomes the bottleneck. This is the primary target for optimization in future modules (moving to per-core caches).

---

## 2. Ingress & Handoff
**File:** `src/ring.c`, `src/rx.h`

### Design
To decouple the RX thread (I/O) from the Workers (CPU), we use **Single-Producer / Single-Consumer (SPSC) Rings**.

*   **Topology:** 1 RX Thread feeds $N$ Workers via $N$ distinct rings.
*   **Data Transfer:** Only the 8-byte pointer (`pktbuf_t*`) is passed through the ring. The packet data stays in the buffer allocated from the pool.

### API
*   **`ring_push` / `ring_pop`**:
    *   **Lock-Free:** Uses C11 `stdatomic`.
    *   **`memory_order_release` (Producer):** Ensures the pointer written to the slot is visible *before* the `head` index is updated.
    *   **`memory_order_acquire` (Consumer):** Ensures the consumer sees the updated `head` index *before* reading the slot.
    *   *Why?* This allows the RX thread and Worker thread to operate without ever putting the CPU to sleep (no mutexes), maximizing throughput.

---

## 3. Workers
**File:** `src/worker.c`, `include/worker.h`

### Design
Workers are  dataplane. They are designed to be as independent as possible, though they currently share the global memory pool.

*   **Private State:**
    *   `rx_ring`: Dedicated input channel.
    *   `rule_stats`: **Private** array of counters.
*   **Shared State (Read-Only):**
    *   `rt`: The Rule Table.
    *   `tx`: The TX context.
*   **Shared State (Write):**
    *   `pool`: The global packet pool (via Mutex).

### API
*   **`worker_init`**:
    *   Allocates `w->rule_stats` based on `rt->capacity`.
    *   *Reason:* We allocate stats memory here so `worker_main` never has to check for allocation or resize arrays.
*   **`worker_main`**:
    *   **Batchless Processing:** Currently processes one packet at a time (`ring_pop` -> `parse` -> `match` -> `free`).
    *   **Lock-Free Stats:** Increments `w->rule_stats[id]` directly. Since no other thread touches this memory, it requires no atomic instructions, which is a significant performance win.

---

## 4. Policy
**File:** `src/rule_table.c` (implied context), `src/worker.c`

### Design
The classification engine is a linear list of rules sorted by priority.

*   **Lookup:** `rule_table_match` iterates through the array.
*   **Semantics:** First-match wins.
*   **Thread Safety:** The table is effectively immutable during the packet processing phase. Workers read it concurrently without locks.

---

## 5. Observability
**File:** `src/main.c` (`stats_thread_func`)

### Design
To view the system state without slowing it down, we use a separate thread.

*   **Mechanism:** The thread wakes up every 1 second.
*   **Aggregation:** It loops through all `worker_t` structures and sums their private `rule_stats`.
*   **Consistency:** It relies on the eventual consistency of reading aligned 64-bit integers. It does not lock the workers.

### API
*   **`stats_thread_func`**:
    *   *Why `printf` with ANSI codes?* To create a "Dashboard" experience (clearing screen, fixed columns) rather than a scrolling log file.
    *   *Why iterate workers?* This pulls the complexity of aggregation out of the packet path. The workers just increment; the stats thread does the heavy lifting of summing and formatting.

---

## Summary of Current Architecture

| Component | Implementation Status | Bottleneck / Characteristic |
| :--- | :--- | :--- |
| **Memory** | Global Pool (`pktbuf_pool_t`) | **High Contention** (Global Mutex) |
| **Ingress** | `libpcap` + SPSC Rings | **Efficient** (Lock-free handoff) |
| **Processing** | `worker_main` | **Efficient** (No logic locks, but hits memory lock on free) |
| **Stats** | Per-Worker Arrays | **Perfect** (Zero contention) |
| **Scaling** | Multi-thread | Limited by the Global Pool Lock |