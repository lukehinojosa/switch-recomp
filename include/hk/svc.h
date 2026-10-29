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
    HK_SVC_CLOSE_HANDLE = 0x16,
    HK_SVC_CONNECT_TO_NAMED_PORT = 0x1f,
    HK_SVC_SEND_SYNC_REQUEST = 0x21,
    HK_SVC_CREATE_SESSION = 0x40,
    HK_SVC_ACCEPT_SESSION = 0x41,
    HK_SVC_REPLY_AND_RECEIVE = 0x43,
    HK_SVC_MANAGE_NAMED_PORT = 0x71,
};

/* Runs one supervisor call for a guest thread. Unknown calls return
 * NotImplemented in w0 so a runtime can stop loudly at the first gap. */
void hk_svc(hk_thread* thread, uint32_t id, hk_regs* regs);

#ifdef __cplusplus
}
#endif

#endif
