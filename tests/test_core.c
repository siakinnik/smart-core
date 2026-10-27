// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 siakinnik
// Host tests for smart-core: framing, every message type, validation,
// visibility rules, persistence, secure sessions and pairing. Uses a mock
// port that records packets, and plays the host side of the Noise handshake
// with the core's own Noise code (cross-checked against an independent
// implementation in tests/test_noise_interop.py).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher-ed25519.h"
#include "monocypher.h"
#include "smart_core.h"

static int failures = 0;
#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
            failures++;                                                   \
        }                                                                 \
    } while (0)

static const uint8_t PROLOGUE[] = "smart-core/2";  // without the terminating NUL below

// ---------- the host side of every session ----------
// A test host either speaks plain packets (trusted session) or runs a Noise
// session; mock_send decrypts what the core sends to it.
typedef struct {
    bool secure;
    noise_hs_t hs;
    noise_cipher_t tx, rx;
    uint8_t msg2[128];
    size_t msg2_len;
    int reject;   // reason of the last REJECT, 0 if none
    bool closed;  // the core asked the port to hang up
} host_t;

static host_t hosts[SMART_MAX_SESSIONS];

// two host identities
static uint8_t host_sk[2][32], host_pk[2][32];

// ---------- mock port ----------
#define MAX_SENT 64
typedef struct {
    uint8_t session;
    uint8_t type, seq;
    uint8_t payload[512];
    size_t len;
} packet_t;

static packet_t sent[MAX_SENT];
static int n_sent;
static uint32_t fake_ms;

typedef struct {
    char key[16];
    uint8_t data[300];
    size_t len;
} stored_t;
static stored_t store[32];
static int n_store;
static int n_writes;

static uint32_t rng_state = 0x9E3779B9;

static uint32_t mock_millis(void *ctx) { (void)ctx; return fake_ms; }

static void record(uint8_t session, const uint8_t *raw, size_t n)
{
    if (n_sent < MAX_SENT && n >= 2) {
        packet_t *p = &sent[n_sent++];
        p->session = session;
        p->type = raw[0];
        p->seq = raw[1];
        p->len = n - 2;
        memcpy(p->payload, raw + 2, p->len);
    }
}

static int mock_send(void *ctx, uint8_t session, const uint8_t *data, size_t len)
{
    (void)ctx;
    // every frame is 00 COBS 00
    CHECK(len >= 2 && data[0] == 0 && data[len - 1] == 0);
    for (size_t i = 1; i + 1 < len; i++)
        CHECK(data[i] != 0);
    uint8_t raw[600];
    size_t n = smart_cobs_decode(data + 1, len - 2, raw, sizeof(raw));
    host_t *h = &hosts[session];

    if (!h->secure) {
        CHECK(n >= 4);
        uint16_t crc = (uint16_t)(raw[n - 2] | (raw[n - 1] << 8));
        CHECK(smart_crc16(raw, n - 2) == crc);
        record(session, raw, n - 2);
        return 0;
    }
    CHECK(n >= 2);
    switch (raw[0]) {
    case 0xA2:
        memcpy(h->msg2, raw + 1, n - 1);
        h->msg2_len = n - 1;
        break;
    case 0xA4: {
        uint8_t plain[600];
        CHECK(noise_decrypt(&h->rx, raw + 1, n - 1, plain));
        record(session, plain, n - 1 - NOISE_TAG_LEN);
        break;
    }
    case 0xA5:
        CHECK(n == 2);
        h->reject = raw[1];
        break;
    default:
        CHECK(!"unexpected frame kind");
    }
    return 0;
}

static int mock_read(void *ctx, const char *key, void *buf, size_t cap)
{
    (void)ctx;
    for (int i = 0; i < n_store; i++)
        if (!strcmp(store[i].key, key)) {
            if (store[i].len > cap)
                return -1;
            memcpy(buf, store[i].data, store[i].len);
            return (int)store[i].len;
        }
    return -1;
}

static int mock_write(void *ctx, const char *key, const void *data, size_t len)
{
    (void)ctx;
    n_writes++;
    CHECK(strlen(key) <= 15 && len <= sizeof(store[0].data));
    for (int i = 0; i < n_store; i++)
        if (!strcmp(store[i].key, key)) {
            memcpy(store[i].data, data, len);
            store[i].len = len;
            return 0;
        }
    strcpy(store[n_store].key, key);
    memcpy(store[n_store].data, data, len);
    store[n_store++].len = len;
    return 0;
}

// deterministic "random" for repeatable tests (xorshift32)
static void mock_random(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 17;
        rng_state ^= rng_state << 5;
        buf[i] = (uint8_t)(rng_state >> 24);
    }
}

static void mock_close(void *ctx, uint8_t session)
{
    (void)ctx;
    hosts[session].closed = true;
}

static const smart_port_t port = { NULL, mock_millis, mock_send, mock_read, mock_write, mock_random, mock_close };

// ---------- helpers ----------
static void send_frame(smart_core_t *c, uint8_t session, const uint8_t *body, size_t len)
{
    uint8_t enc[700];
    enc[0] = 0;
    size_t n = smart_cobs_encode(body, len, enc + 1, sizeof(enc) - 2);
    CHECK(n > 0);
    enc[n + 1] = 0;
    smart_session_feed(c, session, enc, n + 2);
}

static void send_to(smart_core_t *c, uint8_t session, uint8_t type, uint8_t seq, const uint8_t *payload, size_t len)
{
    uint8_t raw[600];
    raw[0] = type;
    raw[1] = seq;
    if (len)
        memcpy(raw + 2, payload, len);
    if (hosts[session].secure) {
        uint8_t body[620];
        body[0] = 0xA4;
        noise_encrypt(&hosts[session].tx, raw, len + 2, body + 1);
        send_frame(c, session, body, 1 + len + 2 + NOISE_TAG_LEN);
        return;
    }
    uint16_t crc = smart_crc16(raw, len + 2);
    raw[len + 2] = (uint8_t)crc;
    raw[len + 3] = (uint8_t)(crc >> 8);
    send_frame(c, session, raw, len + 4);
}

static packet_t *find(uint8_t session, uint8_t type)
{
    for (int i = 0; i < n_sent; i++)
        if (sent[i].session == session && sent[i].type == type)
            return &sent[i];
    return NULL;
}

static int count(uint8_t session, uint8_t type)
{
    int k = 0;
    for (int i = 0; i < n_sent; i++)
        k += sent[i].session == session && sent[i].type == type;
    return k;
}

static void reset_sent(void) { n_sent = 0; }

static void make_host_keys(void)
{
    for (int i = 0; i < 2; i++) {
        memset(host_sk[i], 0x11 * (i + 1), 32);
        noise_public_key(host_pk[i], host_sk[i]);
    }
}

// A trusted (USB) session.
static uint8_t open_usb(smart_core_t *c)
{
    uint8_t s = smart_session_open(c, true);
    if (s < SMART_MAX_SESSIONS)
        memset(&hosts[s], 0, sizeof(hosts[s]));
    return s;
}

// An untrusted session as host `who`; runs the whole handshake. Returns the
// session; hosts[s].reject / .closed tell whether the device let it in.
static uint8_t connect_as(smart_core_t *c, int who)
{
    uint8_t s = smart_session_open(c, false);
    CHECK(s < SMART_MAX_SESSIONS);
    host_t *h = &hosts[s];
    memset(h, 0, sizeof(*h));
    h->secure = true;

    uint8_t e[32], body[1 + 96];
    mock_random(NULL, e, 32);
    noise_hs_init(&h->hs, PROLOGUE, sizeof(PROLOGUE) - 1, host_sk[who], host_pk[who], e);
    body[0] = 0xA1;
    noise_xx_write1(&h->hs, NULL, 0, body + 1);
    send_frame(c, s, body, 1 + NOISE_XX_MSG1_LEN(0));
    CHECK(h->msg2_len == NOISE_XX_MSG2_LEN(0));
    CHECK(noise_xx_read2(&h->hs, h->msg2, h->msg2_len, NULL));
    CHECK(noise_equal32(h->hs.rs, smart_public_key(c)));  // it's really this device
    body[0] = 0xA3;
    CHECK(noise_xx_write3(&h->hs, NULL, 0, body + 1, &h->tx, &h->rx));
    send_frame(c, s, body, 1 + NOISE_XX_MSG3_LEN(0));
    return s;
}

// Pair host `who` over a short-lived USB session, the way a user would.
static void pair_over_usb(smart_core_t *c, int who)
{
    uint8_t u = open_usb(c);
    send_to(c, u, 0x06, 99, host_pk[who], 32);
    CHECK(find(u, 0x84) != NULL);
    smart_session_close(c, u);
}

// An untrusted session as an already paired host 0.
static uint8_t open_net(smart_core_t *c)
{
    if (!smart_public_key(c))
        smart_load(c);
    pair_over_usb(c, 0);
    uint8_t s = connect_as(c, 0);
    CHECK(hosts[s].reject == 0 && !hosts[s].closed && smart_session_authenticated(c, s));
    return s;
}

// ---------- device under test ----------
static const char *const EFFECTS[] = { "solid", "rainbow", "fire" };
static uint8_t P_POWER, P_BRIGHT, P_COLOR, P_EFFECT, P_SPEED16, P_OFFSET, P_SSID, P_PASS, P_IP, P_RESET;
static char ssid[33], pass[65], ip[16];

static uint8_t changed_ids[32];
static int changed_n, change_calls;

static smart_pairing_event_t pairing_events[16];
static int n_pairing_events;

static void on_change(smart_core_t *c, const uint8_t *ids, uint8_t n, void *user)
{
    (void)c; (void)user;
    change_calls++;
    changed_n = n;
    memcpy(changed_ids, ids, n);
}

static void on_pairing(smart_core_t *c, smart_pairing_event_t ev, void *user)
{
    (void)c; (void)user;
    if (n_pairing_events < 16)
        pairing_events[n_pairing_events++] = ev;
}

static void make_device(smart_core_t *c)
{
    smart_config_t cfg = { &port, "8C:D0:B2:A8:62:B2", 1, "lumenc3", "2.0.0", on_change, NULL, on_pairing };
    smart_init(c, &cfg);
    smart_rgb_t orange = { 255, 60, 0 };
    P_POWER = smart_prop_bool(c, "light.power", SMART_F_RW | SMART_F_PERSIST, true);
    P_BRIGHT = smart_prop_u8(c, "light.brightness", SMART_F_RW | SMART_F_PERSIST, 1, 255, 160);
    P_COLOR = smart_prop_rgb(c, "light.color", SMART_F_RW | SMART_F_PERSIST, orange);
    P_EFFECT = smart_prop_enum(c, "light.effect", SMART_F_RW | SMART_F_PERSIST, EFFECTS, 3, 1);
    P_SPEED16 = smart_prop_u16(c, "motor.speed", SMART_F_RW, 0, 3000, 0);
    P_OFFSET = smart_prop_i32(c, "test.offset", SMART_F_RW, -1000, 1000, -5);
    ssid[0] = pass[0] = ip[0] = 0;
    P_SSID = smart_prop_str(c, "sys.wifi_ssid", SMART_F_RW | SMART_F_LOCAL, ssid, 32);
    P_PASS = smart_prop_str(c, "sys.wifi_pass", SMART_F_WRITE | SMART_F_SECRET | SMART_F_LOCAL, pass, 64);
    P_IP = smart_prop_str(c, "sys.ip", SMART_F_READ, ip, 15);
    P_RESET = smart_prop_action(c, "sys.reset", SMART_F_LOCAL);
    change_calls = 0;
    n_pairing_events = 0;
}

// A device fresh out of the factory: empty storage, new key.
static void fresh_device(smart_core_t *c)
{
    n_store = 0;
    make_device(c);
    smart_load(c);
}

static void test_crc_cobs(void)
{
    CHECK(smart_crc16((const uint8_t *)"123456789", 9) == 0x29B1);

    // round-trip lengths around the 254-byte COBS block boundary, with and without zeros
    uint8_t in[600], enc[700], out[600];
    for (size_t len = 1; len < 600; len += (len < 520 ? 1 : 37)) {
        for (int pattern = 0; pattern < 3; pattern++) {
            for (size_t i = 0; i < len; i++)
                in[i] = pattern == 0 ? (uint8_t)(i * 7 + 1) | 1 : pattern == 1 ? 0 : (uint8_t)(i % 5 == 0 ? 0 : i);
            size_t n = smart_cobs_encode(in, len, enc, sizeof(enc));
            CHECK(n > 0);
            for (size_t i = 0; i < n; i++)
                CHECK(enc[i] != 0);
            size_t m = smart_cobs_decode(enc, n, out, sizeof(out));
            CHECK(m == len);
            CHECK(!memcmp(in, out, len));
            // in-place decode
            m = smart_cobs_decode(enc, n, enc, sizeof(enc));
            CHECK(m == len && !memcmp(in, enc, len));
        }
    }
    // output too small
    CHECK(smart_cobs_encode(in, 10, enc, 5) == 0);
    // corrupt input: a code byte pointing past the end
    uint8_t bad[] = { 5, 1, 2 };
    CHECK(smart_cobs_decode(bad, sizeof(bad), out, sizeof(out)) == 0);
}

static void test_hello_describe(void)
{
    smart_core_t c;
    fresh_device(&c);
    uint8_t s = open_net(&c);
    CHECK(s == 0);
    reset_sent();

    uint8_t proto = 1;
    send_to(&c, s, 0x01, 7, &proto, 1);
    packet_t *p = find(s, 0x81);
    CHECK(p && p->seq == 7);
    CHECK(p && p->payload[0] == SMART_PROTO_VERSION && p->payload[1] == 10);
    CHECK(p && p->payload[2] == 1 && p->payload[3] == 0);  // model_id 1
    CHECK(p && p->payload[4] == 17 && !memcmp(p->payload + 5, "8C:D0:B2:A8:62:B2", 17));

    reset_sent();
    send_to(&c, s, 0x02, 8, &P_EFFECT, 1);
    p = find(s, 0x82);
    static const uint8_t want[] = { 3, 5, 0x07, 12, 'l','i','g','h','t','.','e','f','f','e','c','t',
                                    3, 5,'s','o','l','i','d', 7,'r','a','i','n','b','o','w', 4,'f','i','r','e' };
    CHECK(p && p->len == sizeof(want) && !memcmp(p->payload, want, sizeof(want)));

    reset_sent();
    send_to(&c, s, 0x02, 9, &P_SPEED16, 1);
    p = find(s, 0x82);
    CHECK(p && p->payload[1] == 3);
    CHECK(p && p->len == 3 + 1 + 11 + 4 && p->payload[15] == 0 && p->payload[16] == 0 &&
          p->payload[17] == (3000 & 0xFF) && p->payload[18] == (3000 >> 8));

    reset_sent();
    uint8_t unknown = 99;
    send_to(&c, s, 0x02, 10, &unknown, 1);
    p = find(s, 0xEE);
    CHECK(p && p->payload[0] == 3 && p->payload[1] == 99);

    reset_sent();
    uint8_t zero = 0;
    send_to(&c, s, 0x01, 11, &zero, 1);
    p = find(s, 0xEE);
    CHECK(p && p->payload[0] == 7);

    reset_sent();
    send_to(&c, s, 0x05, 12, NULL, 0);
    p = find(s, 0x86);
    CHECK(p && p->seq == 12 && p->len == 0);

    reset_sent();
    send_to(&c, s, 0x42, 13, NULL, 0);
    p = find(s, 0xEE);
    CHECK(p && p->payload[0] == 1);
}

static void test_get_visibility(void)
{
    smart_core_t c;
    fresh_device(&c);
    strcpy(ssid, "home");
    smart_set_str(&c, P_SSID, "home");
    uint8_t net = open_net(&c);
    uint8_t usb = open_usb(&c);
    reset_sent();

    uint8_t all = 0xFF;
    send_to(&c, net, 0x03, 1, &all, 1);
    send_to(&c, usb, 0x03, 2, &all, 1);
    packet_t *pn = find(net, 0x83), *pu = find(usb, 0x83);
    CHECK(pn && pu);
    // untrusted: power, brightness, color, effect, speed, offset, ip; no ssid/pass/reset
    // = 2 + 2 + 4 + 2 + 3 + 5 + 2 (empty ip) = 20 bytes
    CHECK(pn && pn->len == 20);
    // trusted additionally sees the ssid: + 1 + 1 + 4
    CHECK(pu && pu->len == 26);
    // the secret password never appears
    for (size_t i = 0; pu && i + 1 < pu->len; i++)
        CHECK(!(pu->payload[i] == P_PASS));

    reset_sent();
    send_to(&c, net, 0x03, 3, &P_SSID, 1);
    CHECK(find(net, 0xEE) && find(net, 0xEE)->payload[0] == 6);
    reset_sent();
    send_to(&c, usb, 0x03, 4, &P_PASS, 1);
    CHECK(find(usb, 0xEE) && find(usb, 0xEE)->payload[0] == 6);
    reset_sent();
    send_to(&c, usb, 0x03, 5, &P_BRIGHT, 1);
    packet_t *p = find(usb, 0x83);
    CHECK(p && p->len == 2 && p->payload[0] == P_BRIGHT && p->payload[1] == 160);
}

static void test_set(void)
{
    smart_core_t c;
    fresh_device(&c);
    uint8_t net = open_net(&c);
    uint8_t usb = open_usb(&c);

    // valid multi-set: brightness 80, color red, effect fire
    reset_sent();
    uint8_t set1[] = { P_BRIGHT, 80, P_COLOR, 255, 0, 0, P_EFFECT, 2 };
    send_to(&c, net, 0x04, 20, set1, sizeof(set1));
    CHECK(find(net, 0x84) && find(net, 0x84)->seq == 20);
    CHECK(smart_get_u8(&c, P_BRIGHT) == 80 && smart_get_u8(&c, P_EFFECT) == 2);
    CHECK(smart_get_rgb(&c, P_COLOR).g == 0);
    CHECK(change_calls == 1 && changed_n == 3);
    // both sessions get the event, sequence 0
    packet_t *e = find(usb, 0x85);
    CHECK(e && e->seq == 0 && e->len == 2 + 4 + 2);
    CHECK(count(net, 0x85) == 1);

    // setting the same values again: ACK, on_change, but no EVENT
    reset_sent();
    send_to(&c, net, 0x04, 21, set1, sizeof(set1));
    CHECK(find(net, 0x84) && count(net, 0x85) == 0 && count(usb, 0x85) == 0);

    // all-or-nothing: a bad value at the end changes nothing
    reset_sent();
    change_calls = 0;
    uint8_t set2[] = { P_BRIGHT, 10, P_EFFECT, 3 };
    send_to(&c, net, 0x04, 22, set2, sizeof(set2));
    e = find(net, 0xEE);
    CHECK(e && e->payload[0] == 4 && e->payload[1] == P_EFFECT);
    CHECK(smart_get_u8(&c, P_BRIGHT) == 80 && change_calls == 0 && !find(net, 0x84));

    // out of range numbers, bad bool, read-only, truncated, unknown
    struct { uint8_t data[8]; size_t len; uint8_t err; } bad[] = {
        { { P_BRIGHT, 0 }, 2, 4 },
        { { P_POWER, 2 }, 2, 4 },
        { { P_SPEED16, 0xB9, 0x0B }, 3, 4 },          // 3001
        { { P_OFFSET, 0x17, 0xFC, 0xFF, 0xFF }, 5, 4 },  // -1001
        { { P_IP, 0 }, 2, 5 },
        { { P_COLOR, 1, 2 }, 3, 2 },
        { { 77, 1 }, 2, 3 },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        reset_sent();
        send_to(&c, net, 0x04, 30, bad[i].data, bad[i].len);
        e = find(net, 0xEE);
        CHECK(e && e->payload[0] == bad[i].err);
    }
    // empty SET
    reset_sent();
    send_to(&c, net, 0x04, 31, NULL, 0);
    CHECK(find(net, 0xEE) && find(net, 0xEE)->payload[0] == 2);

    // negative i32 round-trips
    reset_sent();
    uint8_t set3[] = { P_OFFSET, 0x18, 0xFC, 0xFF, 0xFF };  // -1000
    send_to(&c, net, 0x04, 32, set3, sizeof(set3));
    CHECK(smart_get_i32(&c, P_OFFSET) == -1000);

    // LOCAL over the network is forbidden, over USB it works; the password stays hidden
    reset_sent();
    uint8_t set4[] = { P_SSID, 4, 'h', 'o', 'm', 'e', P_PASS, 3, 'a', 'b', 'c' };
    send_to(&c, net, 0x04, 40, set4, sizeof(set4));
    CHECK(find(net, 0xEE) && find(net, 0xEE)->payload[0] == 6 && ssid[0] == 0);
    reset_sent();
    send_to(&c, usb, 0x04, 41, set4, sizeof(set4));
    CHECK(find(usb, 0x84) && !strcmp(ssid, "home") && !strcmp(pass, "abc"));
    e = find(usb, 0x85);
    CHECK(e && e->len == 6 && e->payload[0] == P_SSID);  // ssid only, no password
    CHECK(count(net, 0x85) == 0);                       // ssid is LOCAL: the network sees nothing

    // string too long, string with NUL
    reset_sent();
    uint8_t set5[2 + 40] = { P_SSID, 33 };
    memset(set5 + 2, 'x', 33);
    send_to(&c, usb, 0x04, 42, set5, 2 + 33);
    CHECK(find(usb, 0xEE) && find(usb, 0xEE)->payload[0] == 4);
    reset_sent();
    uint8_t set6[] = { P_SSID, 3, 'a', 0, 'b' };
    send_to(&c, usb, 0x04, 43, set6, sizeof(set6));
    CHECK(find(usb, 0xEE) && find(usb, 0xEE)->payload[0] == 4);

    // actions: trigger on_change, no event, LOCAL rules apply
    reset_sent();
    change_calls = 0;
    send_to(&c, net, 0x04, 50, &P_RESET, 1);
    CHECK(find(net, 0xEE) && change_calls == 0);
    reset_sent();
    send_to(&c, usb, 0x04, 51, &P_RESET, 1);
    CHECK(find(usb, 0x84) && change_calls == 1 && changed_n == 1 && changed_ids[0] == P_RESET);
    CHECK(count(usb, 0x85) == 0);
}

static void test_local_set_and_events(void)
{
    smart_core_t c;
    fresh_device(&c);
    uint8_t net = open_net(&c);
    reset_sent();
    CHECK(smart_set_u8(&c, P_BRIGHT, 200));
    CHECK(count(net, 0x85) == 1);
    CHECK(change_calls == 0);  // local changes don't call on_change
    reset_sent();
    CHECK(smart_set_u8(&c, P_BRIGHT, 200));  // unchanged: no event
    CHECK(count(net, 0x85) == 0);
    CHECK(!smart_set_u8(&c, P_BRIGHT, 0));   // out of range
    CHECK(!smart_set_u8(&c, P_EFFECT, 3));
    CHECK(!smart_set_bool(&c, P_BRIGHT, true));  // wrong type
    CHECK(smart_set_u8(&c, P_EFFECT, 0));        // enums use u8
    CHECK(!smart_set_str(&c, P_IP, "0123456789abcdef"));  // 16 > cap 15
    CHECK(smart_set_str(&c, P_IP, "192.168.20.42") && !strcmp(smart_get_str(&c, P_IP), "192.168.20.42"));
}

static void test_persistence(void)
{
    n_store = 0;
    n_writes = 0;
    fake_ms = 1000;
    smart_core_t c;
    make_device(&c);
    smart_load(&c);
    CHECK(smart_get_u8(&c, P_BRIGHT) == 160);  // nothing stored yet

    uint8_t s = open_net(&c);
    n_writes = 0;  // the device key and the paired host were stored by now
    uint8_t set1[] = { P_BRIGHT, 42, P_POWER, 0, P_SPEED16, 10, 0 };
    send_to(&c, s, 0x04, 1, set1, sizeof(set1));
    smart_poll(&c);
    CHECK(n_writes == 0);  // not yet
    fake_ms += SMART_PERSIST_DELAY_MS;
    smart_poll(&c);
    CHECK(n_writes == 2);  // brightness + power; motor.speed isn't PERSIST
    smart_poll(&c);
    CHECK(n_writes == 2);

    smart_set_rgb(&c, P_COLOR, (smart_rgb_t){ 1, 2, 3 });
    smart_flush(&c);
    CHECK(n_writes == 3);

    // a fresh boot restores them
    smart_core_t c2;
    make_device(&c2);
    smart_load(&c2);
    CHECK(smart_get_u8(&c2, P_BRIGHT) == 42 && !smart_get_bool(&c2, P_POWER));
    CHECK(smart_get_rgb(&c2, P_COLOR).b == 3);
    CHECK(smart_get_u16(&c2, P_SPEED16) == 0);

    // a stored value that no longer fits the range is ignored
    for (int i = 0; i < n_store; i++)
        if (store[i].len == 1 && store[i].data[0] == 42)
            store[i].data[0] = 0;
    smart_core_t c3;
    make_device(&c3);
    smart_load(&c3);
    CHECK(smart_get_u8(&c3, P_BRIGHT) == 160);
}

static void test_stream_robustness(void)
{
    smart_core_t c;
    fresh_device(&c);
    uint8_t s = open_usb(&c);
    reset_sent();

    // log text before a packet, a corrupted packet, an oversized run of bytes
    const char *log = "I (123) boot: starting\r\n";
    smart_session_feed(&c, s, (const uint8_t *)log, strlen(log));
    send_to(&c, s, 0x05, 1, NULL, 0);
    CHECK(count(s, 0x86) == 1);

    uint8_t junk[2000];
    memset(junk, 'A', sizeof(junk));
    smart_session_feed(&c, s, junk, sizeof(junk));
    send_to(&c, s, 0x05, 2, NULL, 0);
    CHECK(count(s, 0x86) == 2);

    // flip one bit inside an encoded PING: no reply at all
    uint8_t raw[4] = { 0x05, 3 }, enc[16];
    uint16_t crc = smart_crc16(raw, 2);
    raw[2] = (uint8_t)crc;
    raw[3] = (uint8_t)(crc >> 8);
    enc[0] = 0;
    size_t n = smart_cobs_encode(raw, 4, enc + 1, 14);
    enc[n + 1] = 0;
    enc[2] ^= 0x10;
    int before = n_sent;
    smart_session_feed(&c, s, enc, n + 2);
    CHECK(n_sent == before);

    // packets split across many feed() calls, byte by byte
    uint8_t one[32];
    raw[1] = 4;
    crc = smart_crc16(raw, 2);
    raw[2] = (uint8_t)crc;
    raw[3] = (uint8_t)(crc >> 8);
    one[0] = 0;
    n = smart_cobs_encode(raw, 4, one + 1, 30);
    one[n + 1] = 0;
    for (size_t i = 0; i < n + 2; i++)
        smart_session_feed(&c, s, &one[i], 1);
    CHECK(count(s, 0x86) == 3);

    // closed sessions receive nothing, the slot is reused
    smart_session_close(&c, s);
    CHECK(smart_session_open(&c, false) == s);
}

static void test_get_all_splits(void)
{
    // many string properties: GET FF must split them over several VALUES packets
    smart_core_t c;
    smart_config_t cfg = { &port, "id", 0, "big", "1", NULL, NULL, NULL };
    n_store = 0;
    smart_init(&c, &cfg);
    static char bufs[20][61];
    static const char *names[20] = { "s0","s1","s2","s3","s4","s5","s6","s7","s8","s9",
                                     "s10","s11","s12","s13","s14","s15","s16","s17","s18","s19" };
    for (int i = 0; i < 20; i++) {
        memset(bufs[i], 'a' + i, 60);
        bufs[i][60] = 0;
        CHECK(smart_prop_str(&c, names[i], SMART_F_RW, bufs[i], 60) == i);
    }
    uint8_t s = open_net(&c);
    reset_sent();
    uint8_t all = 0xFF;
    send_to(&c, s, 0x03, 9, &all, 1);
    int k = count(s, 0x83);
    CHECK(k >= 5);
    CHECK(sent[n_sent - 1].type == 0x84 && sent[n_sent - 1].seq == 9);  // ACK closes GET FF
    // every property appears exactly once, all with seq 9
    int seen[20] = { 0 };
    for (int i = 0; i < n_sent; i++) {
        if (sent[i].type != 0x83)
            continue;
        CHECK(sent[i].seq == 9 && sent[i].len <= SMART_MAX_PAYLOAD);
        for (size_t pos = 0; pos < sent[i].len;) {
            uint8_t id = sent[i].payload[pos], len = sent[i].payload[pos + 1];
            CHECK(id < 20 && len == 60);
            seen[id]++;
            pos += 2 + len;
        }
    }
    for (int i = 0; i < 20; i++)
        CHECK(seen[i] == 1);

    // table full
    smart_core_t full;
    smart_init(&full, &cfg);
    for (int i = 0; i < SMART_MAX_PROPS; i++)
        CHECK(smart_prop_bool(&full, "b", SMART_F_RW, false) == i);
    CHECK(smart_prop_bool(&full, "b", SMART_F_RW, false) == SMART_PROP_NONE);
    // invalid registrations
    CHECK(smart_prop_u8(&c, "x", SMART_F_RW, 10, 5, 7) == SMART_PROP_NONE);
    CHECK(smart_prop_u8(&c, "x", SMART_F_RW, 1, 5, 7) == SMART_PROP_NONE);
}


// ---------- crypto building blocks ----------
static void hex(const char *h, uint8_t *out)
{
    for (size_t i = 0; h[2 * i]; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void test_crypto_vectors(void)
{
    // RFC 8439 section 2.8.2: ChaCha20-Poly1305 AEAD, through a fresh
    // Monocypher context the way smart_noise.c uses it
    static const char *plain_text =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    uint8_t key[32], nonce[12], ad[12], ct[114], mac[16], want_mac[16], want_ct_head[16];
    hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key);
    hex("070000004041424344454647", nonce);
    hex("50515253c0c1c2c3c4c5c6c7", ad);
    hex("1ae10b594f09e26a7e902ecbd0600691", want_mac);
    hex("d31a8d34648e60db7b86afbc53ef7ec2", want_ct_head);
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, ct, mac, ad, sizeof(ad), (const uint8_t *)plain_text, 114);
    CHECK(!memcmp(mac, want_mac, 16));
    CHECK(!memcmp(ct, want_ct_head, 16));

    // RFC 7748 section 6.1: X25519
    uint8_t a_sk[32], b_pk[32], shared[32], want[32];
    hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_sk);
    hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", b_pk);
    hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", want);
    crypto_x25519(shared, a_sk, b_pk);
    CHECK(!memcmp(shared, want, 32));

    // a full XX handshake with payloads, then transport both ways
    uint8_t i_sk[32], i_pk[32], r_sk[32], r_pk[32], e1[32], e2[32];
    mock_random(NULL, i_sk, 32);
    mock_random(NULL, r_sk, 32);
    mock_random(NULL, e1, 32);
    mock_random(NULL, e2, 32);
    noise_public_key(i_pk, i_sk);
    noise_public_key(r_pk, r_sk);
    noise_hs_t ini, res;
    noise_cipher_t i_tx, i_rx, r_tx, r_rx;
    noise_hs_init(&ini, PROLOGUE, sizeof(PROLOGUE) - 1, i_sk, i_pk, e1);
    noise_hs_init(&res, PROLOGUE, sizeof(PROLOGUE) - 1, r_sk, r_pk, e2);
    uint8_t m1[64], m2[160], m3[128], p[64];
    noise_xx_write1(&ini, (const uint8_t *)"one", 3, m1);
    noise_xx_read1(&res, m1, NOISE_XX_MSG1_LEN(3), p);
    CHECK(!memcmp(p, "one", 3));
    CHECK(noise_xx_write2(&res, (const uint8_t *)"two!", 4, m2));
    CHECK(noise_xx_read2(&ini, m2, NOISE_XX_MSG2_LEN(4), p));
    CHECK(!memcmp(p, "two!", 4) && noise_equal32(ini.rs, r_pk));
    CHECK(noise_xx_write3(&ini, (const uint8_t *)"3", 1, m3, &i_tx, &i_rx));
    CHECK(noise_xx_read3(&res, m3, NOISE_XX_MSG3_LEN(1), p, &r_tx, &r_rx));
    CHECK(p[0] == '3' && noise_equal32(res.rs, i_pk));

    uint8_t box[64], back[64];
    noise_encrypt(&i_tx, (const uint8_t *)"ping", 4, box);
    CHECK(noise_decrypt(&r_rx, box, 4 + NOISE_TAG_LEN, back) && !memcmp(back, "ping", 4));
    noise_encrypt(&r_tx, (const uint8_t *)"pong", 4, box);
    CHECK(noise_decrypt(&i_rx, box, 4 + NOISE_TAG_LEN, back) && !memcmp(back, "pong", 4));
    // replay of the same message, and a flipped bit, both fail
    noise_encrypt(&i_tx, (const uint8_t *)"x", 1, box);
    CHECK(noise_decrypt(&r_rx, box, 1 + NOISE_TAG_LEN, back));
    CHECK(!noise_decrypt(&r_rx, box, 1 + NOISE_TAG_LEN, back));
    noise_encrypt(&i_tx, (const uint8_t *)"y", 1, box);
    box[0] ^= 1;
    CHECK(!noise_decrypt(&r_rx, box, 1 + NOISE_TAG_LEN, back));

    // a tampered message 2 doesn't authenticate
    noise_hs_init(&ini, PROLOGUE, sizeof(PROLOGUE) - 1, i_sk, i_pk, e1);
    noise_hs_init(&res, PROLOGUE, sizeof(PROLOGUE) - 1, r_sk, r_pk, e2);
    noise_xx_write1(&ini, NULL, 0, m1);
    noise_xx_read1(&res, m1, 32, NULL);
    noise_xx_write2(&res, NULL, 0, m2);
    m2[40] ^= 0x80;
    CHECK(!noise_xx_read2(&ini, m2, NOISE_XX_MSG2_LEN(0), NULL));

    // a different prologue (another protocol) can't complete the handshake
    noise_hs_init(&ini, (const uint8_t *)"other", 5, i_sk, i_pk, e1);
    noise_hs_init(&res, PROLOGUE, sizeof(PROLOGUE) - 1, r_sk, r_pk, e2);
    noise_xx_write1(&ini, NULL, 0, m1);
    noise_xx_read1(&res, m1, 32, NULL);
    noise_xx_write2(&res, NULL, 0, m2);
    CHECK(!noise_xx_read2(&ini, m2, NOISE_XX_MSG2_LEN(0), NULL));
}

// ---------- secure sessions and pairing ----------
static void test_unpaired_rejected(void)
{
    smart_core_t c;
    fresh_device(&c);
    reset_sent();
    uint8_t s = connect_as(&c, 1);
    CHECK(hosts[s].reject == 1 && hosts[s].closed);  // NOT_PAIRED
    CHECK(!smart_session_authenticated(&c, s));
    CHECK(n_sent == 0);  // not a single packet reached it

    // plain packets on an untrusted session are not even looked at
    uint8_t t = smart_session_open(&c, false);
    memset(&hosts[t], 0, sizeof(hosts[t]));
    hosts[t].secure = true;  // decode what comes back as secure frames
    uint8_t raw[] = { 0x01, 1, 1, 0, 0 };
    uint16_t crc = smart_crc16(raw, 3);
    raw[3] = (uint8_t)crc;
    raw[4] = (uint8_t)(crc >> 8);
    send_frame(&c, t, raw, sizeof(raw));
    CHECK(hosts[t].reject == 4 && hosts[t].closed && n_sent == 0);  // HANDSHAKE

    // events never go to a session that hasn't finished the handshake
    uint8_t u = smart_session_open(&c, false);
    memset(&hosts[u], 0, sizeof(hosts[u]));
    hosts[u].secure = true;
    CHECK(smart_set_u8(&c, P_BRIGHT, 99));
    CHECK(n_sent == 0);

    // and a stalled handshake is dropped
    fake_ms += SMART_HANDSHAKE_TIMEOUT_MS;
    smart_poll(&c);
    CHECK(hosts[u].reject == 5 && hosts[u].closed);  // TIMEOUT
}

static void test_pairing_window(void)
{
    smart_core_t c;
    fresh_device(&c);
    CHECK(smart_paired_count(&c) == 0);

    smart_pairing_open(&c, 120000);
    CHECK(smart_pairing_is_open(&c) && n_pairing_events == 1 && pairing_events[0] == SMART_PAIRING_OPENED);
    uint8_t s = connect_as(&c, 0);
    CHECK(hosts[s].reject == 0 && smart_session_authenticated(&c, s));
    CHECK(smart_paired_count(&c) == 1 && !smart_pairing_is_open(&c));
    CHECK(n_pairing_events == 2 && pairing_events[1] == SMART_PAIRING_PAIRED);

    // the new host works, and INFO carries the device key it can pin
    reset_sent();
    uint8_t proto = 2;
    send_to(&c, s, 0x01, 5, &proto, 1);
    packet_t *p = find(s, 0x81);
    CHECK(p && p->len >= 32 && !memcmp(p->payload + p->len - 32, smart_public_key(&c), 32));

    // the same host reconnecting while the window runs is fine
    uint8_t s2 = connect_as(&c, 0);
    CHECK(hosts[s2].reject == 0 && smart_session_authenticated(&c, s2));

    // when the window ends: CLOSED, and a stranger is just turned away
    fake_ms += 120000;
    smart_poll(&c);
    CHECK(n_pairing_events == 3 && pairing_events[2] == SMART_PAIRING_CLOSED);
    uint8_t s3 = connect_as(&c, 1);
    CHECK(hosts[s3].reject == 1);
    CHECK(smart_paired_count(&c) == 1 && n_pairing_events == 3);
    smart_session_close(&c, s);
    smart_session_close(&c, s2);
}

// The window is the owner's consent: the host paired in it may commission
// the device (set LOCAL properties such as Wi-Fi) over an untrusted link,
// until the window ends. Nobody else may.
static void test_window_commissioning(void)
{
    smart_core_t c;
    fresh_device(&c);
    pair_over_usb(&c, 1);  // an older host, paired before
    smart_pairing_open(&c, 60000);
    uint8_t owner = connect_as(&c, 0);
    uint8_t older = connect_as(&c, 1);
    CHECK(smart_session_authenticated(&c, owner) && smart_session_authenticated(&c, older));

    uint8_t set[] = { P_SSID, 4, 'h', 'o', 'm', 'e', P_PASS, 3, 'p', 'w', 'd' };
    reset_sent();
    send_to(&c, older, 0x04, 1, set, sizeof(set));
    CHECK(find(older, 0xEE) && find(older, 0xEE)->payload[0] == 6 && ssid[0] == 0);
    reset_sent();
    send_to(&c, owner, 0x04, 2, set, sizeof(set));
    CHECK(find(owner, 0x84) && !strcmp(ssid, "home") && !strcmp(pass, "pwd"));
    CHECK(count(owner, 0x85) == 1 && count(older, 0x85) == 0);  // only the owner sees the LOCAL ssid change

    // GET FF: the owner sees LOCAL values for now, the older host doesn't
    uint8_t all = 0xFF;
    reset_sent();
    send_to(&c, owner, 0x03, 3, &all, 1);
    send_to(&c, older, 0x03, 4, &all, 1);
    CHECK(find(owner, 0x83) && find(older, 0x83) && find(owner, 0x83)->len > find(older, 0x83)->len);

    // the window ends: the rights go with it
    fake_ms += 60000;
    smart_poll(&c);
    CHECK(pairing_events[n_pairing_events - 1] == SMART_PAIRING_CLOSED);
    reset_sent();
    send_to(&c, owner, 0x04, 5, set, sizeof(set));
    CHECK(find(owner, 0xEE) && find(owner, 0xEE)->payload[0] == 6);
    CHECK(smart_session_authenticated(&c, owner));  // still paired, just not an admin

    // closing the window early does the same, and says so once
    smart_pairing_open(&c, 60000);
    smart_pairing_close(&c);
    smart_pairing_close(&c);
    CHECK(pairing_events[n_pairing_events - 1] == SMART_PAIRING_CLOSED);
    CHECK(pairing_events[n_pairing_events - 2] == SMART_PAIRING_OPENED);
}

static void test_pairing_conflict(void)
{
    smart_core_t c;
    fresh_device(&c);
    smart_pairing_open(&c, 120000);
    uint8_t a = connect_as(&c, 0);  // say this is an intruder, a moment faster
    CHECK(smart_session_authenticated(&c, a));
    fake_ms += 2000;
    uint8_t b = connect_as(&c, 1);  // the owner arrives second
    CHECK(hosts[b].reject == 2);   // CONFLICT
    CHECK(hosts[a].closed && !smart_session_authenticated(&c, a));  // the first one is thrown out too
    CHECK(smart_paired_count(&c) == 0 && !smart_pairing_is_open(&c));
    CHECK(n_pairing_events == 3 && pairing_events[2] == SMART_PAIRING_CONFLICT);
    // neither of them gets back in
    uint8_t again = connect_as(&c, 0);
    CHECK(hosts[again].reject == 1);
}

static void test_pairing_timeout(void)
{
    smart_core_t c;
    fresh_device(&c);
    smart_pairing_open(&c, 10000);
    fake_ms += 10000;
    smart_poll(&c);
    CHECK(!smart_pairing_is_open(&c));
    CHECK(n_pairing_events == 2 && pairing_events[1] == SMART_PAIRING_TIMEOUT);
    uint8_t s = connect_as(&c, 0);
    CHECK(hosts[s].reject == 1);
}

static void test_pair_unpair_messages(void)
{
    smart_core_t c;
    fresh_device(&c);

    // PAIR over USB: physical access is consent
    uint8_t u = open_usb(&c);
    reset_sent();
    send_to(&c, u, 0x06, 1, host_pk[1], 32);
    CHECK(find(u, 0x84) && smart_paired_count(&c) == 1);
    CHECK(n_pairing_events == 1 && pairing_events[0] == SMART_PAIRING_PAIRED);
    send_to(&c, u, 0x06, 2, host_pk[1], 32);  // again: fine, no duplicate, no event
    CHECK(smart_paired_count(&c) == 1 && n_pairing_events == 1);
    reset_sent();
    send_to(&c, u, 0x06, 3, host_pk[1], 31);
    CHECK(find(u, 0xEE) && find(u, 0xEE)->payload[0] == 2);

    // a paired host can't PAIR somebody else over the network
    uint8_t n = connect_as(&c, 1);
    CHECK(smart_session_authenticated(&c, n));
    reset_sent();
    send_to(&c, n, 0x06, 4, host_pk[0], 32);
    CHECK(find(n, 0xEE) && find(n, 0xEE)->payload[0] == 6);
    CHECK(smart_paired_count(&c) == 1);

    // ... nor UNPAIR another host
    reset_sent();
    send_to(&c, n, 0x07, 5, host_pk[0], 32);
    CHECK(find(n, 0xEE) && find(n, 0xEE)->payload[0] == 6);
    // ... nor everybody
    reset_sent();
    send_to(&c, n, 0x07, 6, NULL, 0);
    CHECK(find(n, 0xEE) && find(n, 0xEE)->payload[0] == 2);

    // but it may unpair itself: ACK, then it's gone and disconnected
    reset_sent();
    send_to(&c, n, 0x07, 7, host_pk[1], 32);
    CHECK(find(n, 0x84) && hosts[n].closed && smart_paired_count(&c) == 0);

    // the table fills up
    for (int i = 0; i < SMART_MAX_PAIRED; i++) {
        uint8_t k[32];
        memset(k, i + 1, 32);
        send_to(&c, u, 0x06, 8, k, 32);
    }
    CHECK(smart_paired_count(&c) == SMART_MAX_PAIRED);
    reset_sent();
    send_to(&c, u, 0x06, 9, host_pk[0], 32);
    CHECK(find(u, 0xEE) && find(u, 0xEE)->payload[0] == 8);  // PAIRING_FULL

    // USB unpairs everybody
    reset_sent();
    send_to(&c, u, 0x07, 10, NULL, 0);
    CHECK(find(u, 0x84) && smart_paired_count(&c) == 0);
}

static void test_tampering(void)
{
    smart_core_t c;
    fresh_device(&c);
    uint8_t s = open_net(&c);

    // a frame with a flipped bit: the session is dropped, the SET never applied
    uint8_t raw[] = { 0x04, 1, P_BRIGHT, 7 };
    uint8_t body[1 + sizeof(raw) + NOISE_TAG_LEN];
    body[0] = 0xA4;
    noise_encrypt(&hosts[s].tx, raw, sizeof(raw), body + 1);
    body[3] ^= 0x01;
    send_frame(&c, s, body, sizeof(body));
    CHECK(hosts[s].closed && smart_get_u8(&c, P_BRIGHT) == 160);

    // a replayed frame (same nonce) is rejected the same way
    uint8_t t = connect_as(&c, 0);
    noise_encrypt(&hosts[t].tx, raw, sizeof(raw), body + 1);
    send_frame(&c, t, body, sizeof(body));
    CHECK(smart_get_u8(&c, P_BRIGHT) == 7);
    send_frame(&c, t, body, sizeof(body));
    CHECK(hosts[t].closed);
}

static void test_keys_persist(void)
{
    smart_core_t c;
    fresh_device(&c);
    uint8_t first_key[32];
    memcpy(first_key, smart_public_key(&c), 32);
    pair_over_usb(&c, 0);

    // reboot: same identity, same paired hosts
    smart_core_t c2;
    make_device(&c2);
    smart_load(&c2);
    CHECK(!memcmp(smart_public_key(&c2), first_key, 32));
    CHECK(smart_paired_count(&c2) == 1);
    uint8_t s = connect_as(&c2, 0);
    CHECK(smart_session_authenticated(&c2, s));

    // a factory reset (erased storage) is a new device that knows nobody
    smart_core_t c3;
    fresh_device(&c3);
    CHECK(memcmp(smart_public_key(&c3), first_key, 32) != 0);
    CHECK(smart_paired_count(&c3) == 0);

    // no random source: no key, every untrusted session is refused
    static const smart_port_t no_rng = { NULL, mock_millis, mock_send, mock_read, mock_write, NULL, mock_close };
    smart_core_t c4;
    smart_config_t cfg = { &no_rng, "id", 0, "x", "1", NULL, NULL, NULL };
    n_store = 0;
    smart_init(&c4, &cfg);
    smart_load(&c4);
    CHECK(smart_public_key(&c4) == NULL);
    uint8_t t = smart_session_open(&c4, false);
    memset(&hosts[t], 0, sizeof(hosts[t]));
    hosts[t].secure = true;
    uint8_t body[1 + 32] = { 0xA1 };
    send_frame(&c4, t, body, sizeof(body));
    CHECK(hosts[t].reject == 4 && hosts[t].closed);
}


// ---------- firmware updates ----------
static struct {
    uint8_t image[8192];
    uint32_t total, written;
    int begins, finishes;
    bool finished_ok;
} flash;

static int mock_ota_begin(void *ctx, uint32_t total)
{
    (void)ctx;
    if (total > sizeof(flash.image))
        return -1;
    flash.total = total;
    flash.written = 0;
    flash.begins++;
    return 0;
}

static int mock_ota_write(void *ctx, uint32_t offset, const uint8_t *data, size_t len)
{
    (void)ctx;
    CHECK(offset == flash.written && offset + len <= flash.total);  // strictly in order
    memcpy(flash.image + offset, data, len);
    flash.written += (uint32_t)len;
    return 0;
}

static int mock_ota_finish(void *ctx, bool ok)
{
    (void)ctx;
    flash.finishes++;
    flash.finished_ok = ok;
    return 0;
}

static const smart_port_t ota_port = { NULL, mock_millis, mock_send, mock_read, mock_write, mock_random, mock_close,
                                       mock_ota_begin, mock_ota_write, mock_ota_finish };

static uint8_t sign_sk[2][64], sign_pk[2][32];  // [0] the device's update key, [1] somebody else's

static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static void make_manifest(uint8_t out[SMART_MANIFEST_LEN], const uint8_t *image, uint32_t len,
                          uint16_t model_id, uint32_t security_version, int key)
{
    memset(out, 0, SMART_MANIFEST_LEN);
    memcpy(out, "SMARTFW1", 8);
    out[8] = (uint8_t)model_id;
    out[9] = (uint8_t)(model_id >> 8);
    put32(out + 12, security_version);
    put32(out + 16, len);
    memcpy(out + 20, "2.1.0", 5);
    crypto_sha512(out + 52, image, len);
    memcpy(out + 116, sign_pk[key], 32);
    crypto_ed25519_sign(out + 148, sign_sk[key], out, 148);
}

static void make_ota_device(smart_core_t *c, const uint8_t *ota_key)
{
    n_store = 0;
    smart_config_t cfg = { &ota_port, "8C:D0:B2:A8:62:B2", 1, "lumenc3", "2.0.0", on_change, NULL, on_pairing,
                           ota_key, 3 };
    smart_init(c, &cfg);
    P_POWER = smart_prop_bool(c, "light.power", SMART_F_RW, true);
    smart_load(c);
    memset(&flash, 0, sizeof(flash));
}

// send an image in chunks; returns the error code of the first failure, 0 if all ACKed
static int send_image(smart_core_t *c, uint8_t s, const uint8_t *image, uint32_t len, uint32_t chunk)
{
    uint8_t buf[300];
    for (uint32_t off = 0; off < len; off += chunk) {
        uint32_t n = len - off < chunk ? len - off : chunk;
        put32(buf, off);
        memcpy(buf + 4, image + off, n);
        reset_sent();
        send_to(c, s, 0x09, 20, buf, 4 + n);
        packet_t *e = find(s, 0xEE);
        if (e)
            return e->payload[0];
        CHECK(find(s, 0x84) != NULL);
    }
    return 0;
}

static int ota_begin(smart_core_t *c, uint8_t s, const uint8_t manifest[SMART_MANIFEST_LEN])
{
    reset_sent();
    send_to(c, s, 0x08, 10, manifest, SMART_MANIFEST_LEN);
    packet_t *e = find(s, 0xEE);
    return e ? e->payload[0] : (find(s, 0x84) ? 0 : -1);
}

static int ota_end(smart_core_t *c, uint8_t s)
{
    reset_sent();
    send_to(c, s, 0x0A, 30, NULL, 0);
    packet_t *e = find(s, 0xEE);
    return e ? e->payload[0] : (find(s, 0x84) ? 0 : -1);
}

static void test_ed25519_vector(void)
{
    // RFC 8032 section 7.1, TEST 1 (empty message)
    uint8_t seed[32], pk[32], sk[64], want_pk[32], want_sig[64], sig[64];
    hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed);
    hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", want_pk);
    hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", want_sig);
    crypto_ed25519_key_pair(sk, pk, seed);
    CHECK(!memcmp(pk, want_pk, 32));
    crypto_ed25519_sign(sig, sk, NULL, 0);
    CHECK(!memcmp(sig, want_sig, 64));
    CHECK(crypto_ed25519_check(sig, pk, NULL, 0) == 0);
}

static void test_ota(void)
{
    for (int i = 0; i < 2; i++) {
        uint8_t seed[32];
        memset(seed, 0x40 + i, 32);
        crypto_ed25519_key_pair(sign_sk[i], sign_pk[i], seed);
    }
    static uint8_t image[3000];
    for (size_t i = 0; i < sizeof(image); i++)
        image[i] = (uint8_t)(i * 31 + 7);
    uint8_t manifest[SMART_MANIFEST_LEN];

    // INFO says the device takes updates
    smart_core_t c;
    make_ota_device(&c, sign_pk[0]);
    uint8_t s = open_net(&c);
    reset_sent();
    uint8_t proto = 2;
    send_to(&c, s, 0x01, 1, &proto, 1);
    packet_t *info = find(s, 0x81);
    // ... firmware str, max payload (u16), flags, device key (32)
    CHECK(info && info->len > 35 && (info->payload[info->len - 33] & 0x03) == 0x03);

    // the happy path, over a secure session: image + manifest end up in flash
    make_manifest(manifest, image, sizeof(image), 1, 3, 0);
    CHECK(ota_begin(&c, s, manifest) == 0 && flash.total == sizeof(image) + SMART_MANIFEST_LEN);
    CHECK(send_image(&c, s, image, sizeof(image), 236) == 0);
    CHECK(ota_end(&c, s) == 0);
    CHECK(flash.finishes == 1 && flash.finished_ok);
    CHECK(!memcmp(flash.image, image, sizeof(image)));
    CHECK(!memcmp(flash.image + sizeof(image), manifest, SMART_MANIFEST_LEN));
    smart_manifest_t m;
    CHECK(smart_manifest_parse(flash.image + sizeof(image), &m) && m.image_size == sizeof(image));
    CHECK(m.security_version == 3 && !strcmp(m.version, "2.1.0") && m.model_id == 1);

    // refused manifests: other signer, other model, older security version, broken signature
    make_manifest(manifest, image, sizeof(image), 1, 3, 1);
    CHECK(ota_begin(&c, s, manifest) == 9);
    make_manifest(manifest, image, sizeof(image), 2, 3, 0);
    CHECK(ota_begin(&c, s, manifest) == 9);
    make_manifest(manifest, image, sizeof(image), 1, 2, 0);
    CHECK(ota_begin(&c, s, manifest) == 9);
    make_manifest(manifest, image, sizeof(image), 1, 3, 0);
    manifest[12] = 4;  // raise the security version after signing
    CHECK(ota_begin(&c, s, manifest) == 9);
    CHECK(flash.begins == 1);  // none of those touched the flash
    make_manifest(manifest, image, sizeof(image), 1, 4, 0);  // newer is fine
    CHECK(ota_begin(&c, s, manifest) == 0);

    // out of order: a gap and a repeat are refused
    uint8_t chunk[4 + 10];
    put32(chunk, 10);
    memcpy(chunk + 4, image + 10, 10);
    reset_sent();
    send_to(&c, s, 0x09, 2, chunk, sizeof(chunk));
    CHECK(find(s, 0xEE) && find(s, 0xEE)->payload[0] == 4);
    CHECK(send_image(&c, s, image, 100, 100) == 0);
    put32(chunk, 0);
    reset_sent();
    send_to(&c, s, 0x09, 3, chunk, sizeof(chunk));
    CHECK(find(s, 0xEE) && find(s, 0xEE)->payload[0] == 4);
    // END before everything arrived
    CHECK(ota_end(&c, s) == 4);

    // a tampered image: every chunk is accepted, END finds the hash wrong
    static uint8_t evil[3000];
    memcpy(evil, image, sizeof(image));
    evil[1500] ^= 0x01;
    flash.finishes = 0;
    CHECK(ota_begin(&c, s, manifest) == 0);
    CHECK(flash.finishes == 1 && !flash.finished_ok);  // the half-written one was thrown away
    CHECK(send_image(&c, s, evil, sizeof(evil), 236) == 0);
    CHECK(ota_end(&c, s) == 9);
    CHECK(flash.finishes == 2 && !flash.finished_ok);

    // one update at a time; it dies with its session
    CHECK(ota_begin(&c, s, manifest) == 0);
    uint8_t u = open_usb(&c);
    CHECK(ota_begin(&c, u, manifest) == 10);  // BUSY
    // ... and it can't slip data into somebody else's update either
    put32(chunk, 0);
    memcpy(chunk + 4, image, 10);
    reset_sent();
    send_to(&c, u, 0x09, 4, chunk, sizeof(chunk));
    CHECK(find(u, 0xEE) && find(u, 0xEE)->payload[0] == 4 && flash.written == 0);
    flash.finishes = 0;
    smart_session_close(&c, s);
    CHECK(flash.finishes == 1 && !flash.finished_ok);
    CHECK(ota_begin(&c, u, manifest) == 0);  // over USB it works the same
    CHECK(send_image(&c, u, image, sizeof(image), 200) == 0 && ota_end(&c, u) == 0 && flash.finished_ok);

    // without a key the device takes no updates at all
    smart_core_t d;
    make_ota_device(&d, NULL);
    uint8_t t = open_usb(&d);
    CHECK(ota_begin(&d, t, manifest) == 1);
    CHECK(flash.begins == 0);
}

int main(void)
{
    make_host_keys();
    test_crc_cobs();
    test_crypto_vectors();
    test_hello_describe();
    test_get_visibility();
    test_set();
    test_local_set_and_events();
    test_persistence();
    test_stream_robustness();
    test_get_all_splits();
    test_unpaired_rejected();
    test_pairing_window();
    test_window_commissioning();
    test_pairing_conflict();
    test_pairing_timeout();
    test_pair_unpair_messages();
    test_tampering();
    test_keys_persist();
    test_ed25519_vector();
    test_ota();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
