#define _GNU_SOURCE // pthread_setaffinity_np, CPU_* macros
#include "affinity.h"
#include "log.h"

#include <sched.h>
#include <stdio.h>
#include <unistd.h>

int affinity_get_num_cores(void) {
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs < 1) {
        return -1;
    }
    return (int)nprocs;
}

int affinity_pin_thread(pthread_t thread, int core_id) {
    int num_cores = affinity_get_num_cores();
    if (core_id < 0 || core_id >= num_cores) {
        log_msg(LOG_ERROR, "affinity_pin_thread: core_id %d out of range [0-%d]", core_id,
                num_cores - 1);
        return -1;
    }

    // Represents a bitmask of CPUs, it's a 1024 bit array on Linux x86_64.
    cpu_set_t cpuset;
    // Clears all bits, like `memset(&cpuset, 0, sizeof(cpuset))`.
    CPU_ZERO(&cpuset);
    // Sets the bit at pos `core_id` to 1. Thread may only run on that core.
    CPU_SET((size_t)core_id, &cpuset);

    /*
        1. Kernel validates the CPU mask (core exist and online?)
        2. Updates the thread's cpus_allowed field in task_struct.
        3. If thread is currently running on a disallowed core, it
           immediately triggers a reschedule, i.e thread moved.
    */
    int rc = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (rc != 0) {
        log_msg(LOG_ERROR, "pthread_setaffinity_np failed for code: %d: %d", core_id, rc);
        return -1;
    }

    log_msg(LOG_DEBUG, "Thread pinned to core %d", core_id);
    return 0;
}

int affinity_pin_self(int core_id) {
    // pthread_self() returns the pthread_t handle of the calling thread.

    /* pthread_t is a pointer to a pthread descriptor that contains:
       - kernel thread ID (TID), stack info... */

    /* It's a cleaner API than `affinity_pin_thread`, as you don't have to
       pass around pthread_t. */
    return affinity_pin_thread(pthread_self(), core_id);
}

bool affinity_is_pinned(pthread_t thread, int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    // Reads the current CPI affinity mask from the kernel.
    // Inverse of pthread_setaffinity_np.
    /*
       Returns the mask, it's a single core like {2} if pinned.
       If unpinned, then multiple cores, like {0,1,2,3}.
       Subset: {2,3} if limited by cgroups or taskset. */
    int rc = pthread_getaffinity_np(thread, sizeof(cpuset), &cpuset);
    if (rc != 0) {
        return false;
    }

    // Check if bit `core_id` is set in the mask.
    // If set: 1, if clear: 0
    /* Doesn't guarantee that thread is ONLY pinned to core_id.
       for that, need to verify if only ONE bit is set. */
    return CPU_ISSET((size_t)core_id, &cpuset);
}

void affinity_print(pthread_t thread) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    int rc = pthread_getaffinity_np(thread, sizeof(cpuset), &cpuset);
    if (rc != 0) {
        log_msg(LOG_WARN, "Failed to get thread affinity");
        return;
    }

    // Return the number of CPUs set in the mask.
    // Can be used to check if it's pinned to 1 core or multiple, or unpinned.
    int count = CPU_COUNT(&cpuset);

    int num_cores = affinity_get_num_cores();
    if (num_cores <= 0) {
        log_msg(LOG_WARN, "Thread affinity: %d cores (unknown)", count);
        return;
    }

    // Build core list string.
    char cores_str[256] = {0};
    size_t offset = 0;

    for (int i = 0; i < num_cores; i++) {
        if (CPU_ISSET((size_t)i, &cpuset)) {
            if (offset > 0 && offset < sizeof(cores_str) - 1) {
                int written = snprintf(cores_str + offset, sizeof(cores_str) - offset, ", ");
                if (written > 0) {
                    offset += (size_t)written;
                }
            }
            if (offset < sizeof(cores_str) - 1) {
                int written = snprintf(cores_str + offset, sizeof(cores_str) - offset, "%d", i);
                if (written > 0) {
                    offset += (size_t)written;
                }
            }
        }
    }

    log_msg(LOG_INFO, "Thread affinity: cores {%s} (%d total)", cores_str, count);
}