/* The module client (src/client/module_link.h) for titles written in C, or
 * built with another toolchain: a DLL, so that no C++ runtime is shared.
 *
 * A title starts module_host as a linked child process, connects to the
 * ports the module registers and sends CMIF requests without buffers or
 * handles. Every function is safe to call from any thread; requests are
 * serialized inside the client.
 */
#ifndef HK_MODULE_CLIENT_H
#define HK_MODULE_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(HK_MODULE_CLIENT_BUILD)
#define HK_MODULE_CLIENT_API __declspec(dllexport)
#elif defined(_WIN32)
#define HK_MODULE_CLIENT_API __declspec(dllimport)
#else
#define HK_MODULE_CLIENT_API
#endif

typedef struct hk_module hk_module;
typedef struct hk_module_session hk_module_session;

typedef struct hk_module_reply {
    uint32_t kernel;              /* SendSyncRequest result; nonzero: no reply */
    uint32_t result;              /* the CMIF result */
    const uint8_t *raw;           /* output after the CMIF header, in whole words */
    size_t raw_size;
    hk_module_session **objects;  /* sessions the reply moved; the caller closes each */
    size_t object_count;
    size_t copied_handles;        /* copied handles, closed unused */
    int malformed;                /* the reply had no CMIF output header */
} hk_module_reply;

/* Starts executable with --link and then arguments; process_id is this
 * client's process ID as the module sees it. Null on failure, with the reason
 * in error (if given). */
HK_MODULE_CLIENT_API hk_module *hk_module_start(const char *executable, const char *const *arguments,
                                                size_t argument_count, uint64_t process_id,
                                                char *error, size_t error_size);
/* Kills the child once no session uses it. */
HK_MODULE_CLIENT_API void hk_module_stop(hk_module *module);
HK_MODULE_CLIENT_API int hk_module_running(const hk_module *module);

/* Connects to a port the module registers, waiting up to wait_ms for it to
 * appear. Null if it does not. */
HK_MODULE_CLIENT_API hk_module_session *hk_module_connect(hk_module *module, const char *port, uint32_t wait_ms);
/* One request: raw is the input after the CMIF header; with send_pid the
 * kernel supplies process_id. Returns 0 with reply filled (free it with
 * hk_module_reply_free), or nonzero if the request could not be made. */
HK_MODULE_CLIENT_API int hk_module_request(hk_module_session *session, uint32_t command, const void *raw,
                                           size_t raw_size, int send_pid, hk_module_reply *reply);
/* Frees a reply's raw output and object list, not the sessions in it. */
HK_MODULE_CLIENT_API void hk_module_reply_free(hk_module_reply *reply);
HK_MODULE_CLIENT_API void hk_module_close(hk_module_session *session);

#ifdef __cplusplus
}
#endif

#endif
