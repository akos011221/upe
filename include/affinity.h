#ifndef AFFINITY_H
#define AFFINITY_H

#include <pthread.h>
#include <stdbool.h>

/*
    Get number of available CPU cores.

    Uses sysconf(_SC_NPROCESSORS_ONLN).
        Return number of cores currently ONLINE (>= 1) or -1 on error.
*/
int affinity_get_num_cores(void);

/*
    Pin a thread to a specific CPU core.
    Sets the thread's CPU affinity mask via the sched_setaffinity syscall.
        Return 0 on success, -1 on error (invalid core_id, permission denied...).
*/
int affinity_pin_thread(pthread_t thread, int core_id);

/*
    Pin the CALLING thread to a specific CPU core.

    This is a convenience wrapper around affinity_pin_thread().
    Use this when a thread wants to pin itself.

        Return 0 on success, -1 on error.
*/
int affinity_pin_self(int core_id);

/*
    Get the current CPU affinity mask of a thread.
        Return true if thread is pinned to the specified core_id, false otherwise.
*/
bool affinity_is_pinned(pthread_t thread, int code_id);

/*
    Print the current CPU affinity of a thread.
*/
void affinity_print(pthread_t thread);

#endif