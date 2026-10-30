/* The module client's C interface (include/hk/module_client.h), from C:
 * starts cmif_host, then a request, the PID descriptor, a sub-interface, an
 * unknown command and a missing port. */
#include "hk/module_client.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static int failures = 0;

#define CHECK(condition)                                                                 \
    do {                                                                                 \
        if (!(condition)) {                                                              \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); \
            ++failures;                                                                  \
        }                                                                                \
    } while (0)

int main(void) {
    char host[MAX_PATH + 32];
    DWORD size = GetModuleFileNameA(NULL, host, MAX_PATH);
    while (size && host[size - 1] != '\\' && host[size - 1] != '/') --size;
    memcpy(host + size, "cmif_host.exe", sizeof "cmif_host.exe");

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
        hk_module_close(session);
    }
    CHECK(hk_module_connect(module, "absent", 50) == NULL);
    CHECK(hk_module_running(module));
    hk_module_stop(module);

    if (failures) fprintf(stderr, "%d check(s) failed\n", failures);
    else printf("client_c_test: all checks passed\n");
    return failures != 0;
}
