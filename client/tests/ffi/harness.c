/*
 * The C side of the FFI gate (M9 plan C9): compiled with -Wall -Werror
 * against include/kozane_client.h and the staticlib (built with the
 * test-panic feature), and run under valgrind by
 * crates/client-ffi/tests/c_harness.rs. Exits 2 on a failed check, so
 * that valgrind's --error-exitcode=1 stays distinct.
 *
 * Covers creation and argument checks, the first Scrub, the first
 * InitHello, KZ_ERR_BUFFER, KZ_ERR_BUSY, a refused datagram, the clock
 * check and the panic seam. The full exchange through these functions is
 * crates/client-ffi/tests/exchange.rs: it needs a responder.
 */

#include <stdio.h>
#include <string.h>

#include "kozane_client.h"

static int failures;

#define CHECK(cond, what)                                   \
    do {                                                    \
        if (!(cond)) {                                      \
            fprintf(stderr, "ffi: %s (line %d)\n", what, __LINE__); \
            failures++;                                     \
        }                                                   \
    } while (0)

/* Any bytes do as keys here: nothing decapsulates. */
static void fill(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + i * 131u);
    }
}

int main(void) {
    uint8_t *gw_rp_pub = malloc(KZ_RP_PUB_LEN);
    uint8_t *rp_pub = malloc(KZ_RP_PUB_LEN);
    uint8_t *rp_sk = malloc(KZ_RP_SK_LEN);
    if (!gw_rp_pub || !rp_pub || !rp_sk) {
        fprintf(stderr, "ffi: out of memory\n");
        return 2;
    }
    fill(gw_rp_pub, KZ_RP_PUB_LEN, 1);
    fill(rp_pub, KZ_RP_PUB_LEN, 2);
    fill(rp_sk, KZ_RP_SK_LEN, 3);

    kz_config config;
    memset(&config, 0, sizeof config);
    config.rp_endpoint.family = KZ_FAMILY_IPV4;
    config.rp_endpoint.addr[0] = 192;
    config.rp_endpoint.addr[2] = 2;
    config.rp_endpoint.addr[3] = 1;
    config.rp_endpoint.port = 9999;
    memset(config.gw_wg_pub, 7, sizeof config.gw_wg_pub);
    config.gw_rp_pub = gw_rp_pub;
    config.gw_rp_pub_len = KZ_RP_PUB_LEN;
    kz_keys keys = {rp_pub, KZ_RP_PUB_LEN, rp_sk, KZ_RP_SK_LEN};

    kz_client *c = NULL;
    CHECK(kz_client_new(NULL, &keys, &c) == KZ_ERR_INVALID, "new accepted a null config");
    CHECK(kz_client_new(&config, &keys, NULL) == KZ_ERR_INVALID, "new accepted a null out");
    keys.rp_sk_len = KZ_RP_SK_LEN - 1;
    CHECK(kz_client_new(&config, &keys, &c) == KZ_ERR_INVALID, "new accepted a short rp_sk");
    keys.rp_sk_len = KZ_RP_SK_LEN;
    config.rp_endpoint.family = 5;
    CHECK(kz_client_new(&config, &keys, &c) == KZ_ERR_INVALID, "new accepted an unknown family");
    config.rp_endpoint.family = KZ_FAMILY_IPV4;
    config.rp_endpoint.addr[15] = 1;
    CHECK(kz_client_new(&config, &keys, &c) == KZ_ERR_INVALID, "new accepted a dirty ipv4 address");
    config.rp_endpoint.addr[15] = 0;
    CHECK(c == NULL, "a refused new wrote a handle");

    CHECK(kz_client_new(&config, &keys, &c) == KZ_OK && c != NULL, "new failed");
    /* The library holds its own copy now. */
    memset(rp_sk, 0, KZ_RP_SK_LEN);
    if (c == NULL) {
        return 2;
    }

    uint8_t buf[KZ_MAX_DATAGRAM];
    int kind = -1;
    size_t len = 0;
    uint64_t deadline = 1;

    /* The first action is a Scrub, and it blocks the next on_* call. */
    CHECK(kz_client_on_timer(c, 0) == KZ_ERR_BUSY, "on_timer ran with an action queued");
    CHECK(kz_client_take_action(c, NULL, 1, &kind, &len) == KZ_ERR_INVALID, "take accepted a null buf with cap");
    CHECK(kz_client_take_action(c, NULL, 0, &kind, &len) == KZ_OK, "take of the scrub failed");
    CHECK(kind == KZ_ACTION_SCRUB && len == 0, "the first action is not a scrub");
    CHECK(kz_client_take_action(c, buf, sizeof buf, &kind, &len) == KZ_NONE && kind == 0, "queue not empty");

    CHECK(kz_client_next_deadline(c, &deadline) == KZ_OK && deadline == 0, "no immediate deadline");
    CHECK(kz_client_next_deadline(c, NULL) == KZ_ERR_INVALID, "deadline accepted a null out");

    /* The InitHello: a short buffer keeps it queued. */
    CHECK(kz_client_on_timer(c, 0) == KZ_OK, "on_timer failed");
    CHECK(kz_client_take_action(c, buf, 10, &kind, &len) == KZ_ERR_BUFFER, "short buffer accepted");
    CHECK(kind == KZ_ACTION_SEND && len == KZ_MAX_DATAGRAM, "short buffer: wrong kind or length");
    CHECK(kz_client_on_datagram(c, 0, buf, 4) == KZ_ERR_BUSY, "on_datagram ran with an action queued");
    CHECK(kz_client_take_action(c, buf, 10, &kind, &len) == KZ_ERR_BUFFER, "the action left the queue");
    memset(buf, 0, sizeof buf);
    CHECK(kz_client_take_action(c, buf, sizeof buf, &kind, &len) == KZ_OK, "take of the InitHello failed");
    CHECK(kind == KZ_ACTION_SEND && len == KZ_MAX_DATAGRAM && buf[0] == 0x81, "not an InitHello");
    CHECK(kz_client_take_action(c, buf, sizeof buf, &kind, &len) == KZ_NONE, "queue not empty");

    /* A datagram that is no message, and time going backwards. */
    memset(buf, 0x99, 64);
    CHECK(kz_client_on_datagram(c, 5, buf, 64) == KZ_ERR_REJECTED, "garbage accepted");
    CHECK(kz_client_on_datagram(c, 5, NULL, 0) == KZ_ERR_INVALID, "null datagram accepted");
    CHECK(kz_client_on_timer(c, 4) == KZ_ERR_CLOCK, "time went backwards");

    /* A panic is KZ_ERR_INTERNAL, and the handle stays poisoned. */
    CHECK(kz_client_on_timer(c, UINT64_MAX) == KZ_ERR_INTERNAL, "panic not caught");
    CHECK(kz_client_on_timer(c, 6) == KZ_ERR_INTERNAL, "poisoned handle ran");
    CHECK(kz_client_next_deadline(c, &deadline) == KZ_ERR_INTERNAL, "poisoned handle answered");
    kz_client_free(c);

    /* Freed with actions still queued: the PSK slots are wiped on free. */
    kz_client *d = NULL;
    CHECK(kz_client_new(&config, &keys, &d) == KZ_OK, "second new failed");
    kz_client_free(d);
    kz_client_free(NULL);
    CHECK(kz_client_on_timer(NULL, 0) == KZ_ERR_INVALID, "null handle accepted");

    free(gw_rp_pub);
    free(rp_pub);
    free(rp_sk);
    if (failures != 0) {
        fprintf(stderr, "ffi: %d check(s) failed\n", failures);
        return 2;
    }
    printf("ffi harness: ok\n");
    return 0;
}
