/* The module client's C interface (include/hk/module_client.h), from C:
 * starts cmif_host, then a request, the PID descriptor, a sub-interface, an
 * unknown command, an event and a missing port. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L /* readlink, under -std=c11 */
#endif
#include "hk/module_client.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define HOST_NAME "cmif_host.exe"
#else
#include <unistd.h>
#define MAX_PATH 4096
#define HOST_NAME "cmif_host"
#endif

static int failures = 0;

#define CHECK(condition)                                                                 \
    do {                                                                                 \
        if (!(condition)) {                                                              \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); \
            ++failures;                                                                  \
        }                                                                                \
    } while (0)

static int changes = 0;
static char history[16];

static void watched(void *user, int signaled) {
    (void)user;
    if (changes < (int)sizeof history - 1) history[changes++] = signaled ? '1' : '0';
}

int main(void) {
    char host[MAX_PATH + 32];
#ifdef _WIN32
    size_t size = GetModuleFileNameA(NULL, host, MAX_PATH);
#else
    ssize_t got = readlink("/proc/self/exe", host, MAX_PATH);
    size_t size = got > 0 ? (size_t)got : 0;
#endif
    while (size && host[size - 1] != '\\' && host[size - 1] != '/') --size;
    memcpy(host + size, HOST_NAME, sizeof HOST_NAME);

    char error[256] = "";
    hk_module *module = hk_module_start(host, NULL, 0, 0x1234567890ull, error, sizeof error);
    CHECK(module != NULL);
    if (!module) {
        fprintf(stderr, "start: %s\n", error);
        return 1;
    }
    CHECK(hk_module_start("absent.exe", NULL, 0, 0, error, sizeof error) == NULL && error[0]);

    hk_module_session *session = hk_module_connect(module, "test", 10000);
    CHECK(session != NULL);
    if (session) {
        const unsigned char input[7] = {1, 2, 3, 4, 5, 6, 7};
        hk_module_reply reply;
        CHECK(hk_module_request(session, 0, input, sizeof input, 0, &reply) == 0);
        CHECK(reply.kernel == 0 && reply.result == 0 && !reply.malformed);
        CHECK(reply.raw_size == 16 && memcmp(reply.raw, input, sizeof input) == 0);
        hk_module_reply_free(&reply);

        const unsigned long long placeholder = 0;
        unsigned long long pid = 0;
        CHECK(hk_module_request(session, 2, &placeholder, 8, 1, &reply) == 0);
        CHECK(reply.result == 0 && reply.raw_size == 8);
        if (reply.raw_size == 8) memcpy(&pid, reply.raw, 8);
        CHECK(pid == 0x1234567890ull);
        hk_module_reply_free(&reply);

        CHECK(hk_module_request(session, 1, NULL, 0, 0, &reply) == 0);
        CHECK(reply.result == 0 && reply.object_count == 1);
        if (reply.object_count == 1) {
            hk_module_reply again;
            CHECK(hk_module_request(reply.objects[0], 0, input, sizeof input, 0, &again) == 0);
            CHECK(again.result == 0 && again.raw_size == 16);
            hk_module_reply_free(&again);
            hk_module_close(reply.objects[0]);
        }
        hk_module_reply_free(&reply);

        CHECK(hk_module_request(session, 7, NULL, 0, 0, &reply) == 0 && reply.result != 0);
        hk_module_reply_free(&reply);

        /* An event: the host's changes reach the mirror before the reply that
         * follows them, and the watcher sees each. */
        CHECK(hk_module_request(session, 4, NULL, 0, 0, &reply) == 0);
        CHECK(reply.result == 0 && reply.event_count == 1 && reply.copied_handles == 0);
        if (reply.event_count == 1) {
            hk_module_event *event = reply.events[0];
            hk_module_reply step;
            CHECK(!hk_module_event_signaled(event));
            CHECK(hk_module_event_wait(event, 1000000) == 0);
            hk_module_event_watch(event, watched, NULL);
            CHECK(hk_module_request(session, 5, NULL, 0, 0, &step) == 0 && step.result == 0);
            hk_module_reply_free(&step);
            CHECK(hk_module_event_signaled(event));
            CHECK(hk_module_event_wait(event, -1) == 1);
            hk_module_event_clear(event);
            CHECK(!hk_module_event_signaled(event));
            CHECK(hk_module_request(session, 5, NULL, 0, 0, &step) == 0 && step.result == 0);
            hk_module_reply_free(&step);
            CHECK(hk_module_request(session, 6, NULL, 0, 0, &step) == 0 && step.result == 0);
            hk_module_reply_free(&step);
            CHECK(!hk_module_event_signaled(event));
            hk_module_event_watch(event, NULL, NULL);
            CHECK(changes == 4 && strcmp(history, "1010") == 0);
            hk_module_event_close(event);
        }
        hk_module_reply_free(&reply);
        hk_module_close(session);
    }
    CHECK(hk_module_connect(module, "absent", 50) == NULL);
    CHECK(hk_module_running(module));
    hk_module_stop(module);

    if (failures) fprintf(stderr, "%d check(s) failed\n", failures);
    else printf("client_c_test: all checks passed\n");
    return failures != 0;
}
