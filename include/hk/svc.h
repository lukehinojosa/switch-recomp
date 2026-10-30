/* Supervisor-call entry for guest code (recompiled or authored).
 *
 * Plain C so generated code in either C or C++ can call it. Arguments and
 * results follow the AArch64 Horizon convention: inputs in x0..x7, the result
 * code in w0, outputs from x1 upward.
 */
#ifndef HK_SVC_H
#define HK_SVC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hk_thread hk_thread;

typedef struct hk_regs {
    uint64_t x[8];
} hk_regs;

enum {
    HK_SVC_SIGNAL_EVENT = 0x11,
    HK_SVC_CLEAR_EVENT = 0x12,
    HK_SVC_CLOSE_HANDLE = 0x16,
    HK_SVC_RESET_SIGNAL = 0x17,
    HK_SVC_WAIT_SYNCHRONIZATION = 0x18,
    HK_SVC_CANCEL_SYNCHRONIZATION = 0x19,
    HK_SVC_ARBITRATE_LOCK = 0x1a,
    HK_SVC_ARBITRATE_UNLOCK = 0x1b,
    HK_SVC_WAIT_PROCESS_WIDE_KEY_ATOMIC = 0x1c,
    HK_SVC_SIGNAL_PROCESS_WIDE_KEY = 0x1d,
    HK_SVC_CONNECT_TO_NAMED_PORT = 0x1f,
    HK_SVC_SEND_SYNC_REQUEST = 0x21,
    HK_SVC_GET_THREAD_ID = 0x25,
    HK_SVC_CREATE_SESSION = 0x40,
    HK_SVC_ACCEPT_SESSION = 0x41,
    HK_SVC_REPLY_AND_RECEIVE = 0x43,
    HK_SVC_CREATE_EVENT = 0x45,
    HK_SVC_MAP_SHARED_MEMORY = 0x13,
    HK_SVC_UNMAP_SHARED_MEMORY = 0x14,
    HK_SVC_CREATE_TRANSFER_MEMORY = 0x15,
    HK_SVC_CREATE_SHARED_MEMORY = 0x50,
    HK_SVC_MANAGE_NAMED_PORT = 0x71,
};

/* Pseudo-handles every thread can use. */
enum {
    HK_CURRENT_THREAD = 0xFFFF8000,
    HK_CURRENT_PROCESS = 0xFFFF8001,
};

/* Runs one supervisor call for a guest thread. Unknown calls return
 * NotImplemented in w0 so a runtime can stop loudly at the first gap. */
void hk_svc(hk_thread* thread, uint32_t id, hk_regs* regs);

#ifdef __cplusplus
}
#endif

#endif
