// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 siakinnik
// Fake smart-core device on TCP for testing hosts without hardware.
//
//   smart_emulator [port] [pairing_seconds]   (port 0 or none = any free port)
//
// Prints "PORT <n>" once listening. Every TCP connection is an untrusted
// session that must do the Noise handshake as a paired host; a connection
// from 127.0.0.2 counts as trusted ("USB"): plain packets, LOCAL properties,
// PAIR. With pairing_seconds the pairing window opens at start. Pairing
// events are printed as "PAIRING <event>". Ctrl+C to stop.
//
// OTA: with SMART_OTA_KEY=<64 hex digits> (an Ed25519 public key) in the
// environment the emulator takes signed updates into memory and prints
// "OTA installed <bytes> <first 16 hex digits of the image's SHA-512>".
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "smart_core.h"

static int fds[SMART_MAX_SESSIONS];

static uint32_t em_millis(void *ctx)
{
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static int em_send(void *ctx, uint8_t session, const uint8_t *data, size_t len)
{
    (void)ctx;
    if (session >= SMART_MAX_SESSIONS || fds[session] < 0)
        return -1;
    return send(fds[session], data, len, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
}

static void em_random(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, len, f) != len) {
        perror("/dev/urandom");
        exit(1);
    }
    fclose(f);
}

static void em_close(void *ctx, uint8_t session)
{
    (void)ctx;
    if (session < SMART_MAX_SESSIONS && fds[session] >= 0) {
        close(fds[session]);
        fds[session] = -1;
    }
}

static uint8_t ota_buf[1 << 20];
static uint32_t ota_total, ota_written;

static int em_ota_begin(void *ctx, uint32_t total)
{
    (void)ctx;
    if (total > sizeof(ota_buf))
        return -1;
    ota_total = total;
    ota_written = 0;
    return 0;
}

static int em_ota_write(void *ctx, uint32_t offset, const uint8_t *data, size_t len)
{
    (void)ctx;
    if (offset != ota_written || offset + len > ota_total)
        return -1;
    memcpy(ota_buf + offset, data, len);
    ota_written += (uint32_t)len;
    return 0;
}

static int em_ota_finish(void *ctx, bool ok)
{
    (void)ctx;
    if (!ok) {
        printf("OTA aborted\n");
    } else {
        uint8_t hash[64];
        smart_hash_t h;
        smart_hash_init(&h);
        smart_hash_update(&h, ota_buf, ota_total - SMART_MANIFEST_LEN);
        smart_hash_final(&h, hash);
        printf("OTA installed %u ", (unsigned)ota_total);
        for (int i = 0; i < 8; i++)
            printf("%02x", hash[i]);
        printf("\n");
    }
    fflush(stdout);
    return 0;
}

static void on_pairing(smart_core_t *c, smart_pairing_event_t ev, void *user)
{
    (void)c; (void)user;
    static const char *const names[] = { "opened", "paired", "conflict", "timeout", "closed" };
    printf("PAIRING %s\n", names[ev]);
    fflush(stdout);
}

static const char *const EFFECTS[] = { "solid", "rainbow", "fire", "comet", "twinkle", "breathe", "chase" };
static uint8_t P_RESET, P_REBOOT;
static char ssid[33], pass[65], ip[16] = "127.0.0.1";

static void on_change(smart_core_t *c, const uint8_t *ids, uint8_t n, void *user)
{
    (void)c; (void)user;
    for (uint8_t i = 0; i < n; i++) {
        if (ids[i] == P_RESET)
            printf("ACTION reset\n");
        else if (ids[i] == P_REBOOT)
            printf("ACTION reboot\n");
        else
            printf("CHANGED %u\n", ids[i]);
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 0;
    int pairing_s = argc > 2 ? atoi(argv[2]) : 0;
    static const smart_port_t smart_port = { NULL, em_millis, em_send, NULL, NULL, em_random, em_close,
                                             em_ota_begin, em_ota_write, em_ota_finish };
    static smart_core_t core;
    static uint8_t ota_key[32];
    const char *key_hex = getenv("SMART_OTA_KEY");
    bool have_key = key_hex && strlen(key_hex) == 64;
    for (int i = 0; have_key && i < 32; i++) {
        unsigned v;
        have_key = sscanf(key_hex + 2 * i, "%2x", &v) == 1;
        ota_key[i] = (uint8_t)v;
    }
    smart_config_t cfg = { &smart_port, "02:00:00:00:00:01", 1, "lumenc3", "emulator", on_change, NULL, on_pairing,
                           have_key ? ota_key : NULL, 2 };
    smart_init(&core, &cfg);

    smart_prop_bool(&core, "light.power", SMART_F_RW | SMART_F_PERSIST, true);
    smart_prop_u8(&core, "light.brightness", SMART_F_RW | SMART_F_PERSIST, 1, 255, 160);
    smart_prop_rgb(&core, "light.color", SMART_F_RW | SMART_F_PERSIST, (smart_rgb_t){ 255, 60, 0 });
    smart_prop_enum(&core, "light.effect", SMART_F_RW | SMART_F_PERSIST, EFFECTS, 7, 1);
    smart_prop_u8(&core, "light.speed", SMART_F_RW | SMART_F_PERSIST, 1, 100, 50);
    smart_prop_str(&core, "sys.wifi_ssid", SMART_F_RW | SMART_F_LOCAL, ssid, 32);
    smart_prop_str(&core, "sys.wifi_pass", SMART_F_WRITE | SMART_F_SECRET | SMART_F_LOCAL, pass, 64);
    smart_prop_str(&core, "sys.ip", SMART_F_READ, ip, 15);
    P_REBOOT = smart_prop_action(&core, "sys.reboot", 0);
    P_RESET = smart_prop_action(&core, "sys.reset", SMART_F_LOCAL);
    smart_load(&core);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) || listen(lfd, 4)) {
        perror("bind/listen");
        return 1;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (struct sockaddr *)&addr, &alen);
    printf("PORT %u\n", ntohs(addr.sin_port));
    fflush(stdout);
    if (pairing_s > 0)
        smart_pairing_open(&core, (uint32_t)pairing_s * 1000);

    for (int i = 0; i < SMART_MAX_SESSIONS; i++)
        fds[i] = -1;

    for (;;) {
        struct pollfd pfd[1 + SMART_MAX_SESSIONS];
        int map[1 + SMART_MAX_SESSIONS], n = 0;
        pfd[n].fd = lfd;
        pfd[n].events = POLLIN;
        map[n++] = -1;
        for (int s = 0; s < SMART_MAX_SESSIONS; s++)
            if (fds[s] >= 0) {
                pfd[n].fd = fds[s];
                pfd[n].events = POLLIN;
                map[n++] = s;
            }
        poll(pfd, (nfds_t)n, 100);

        if (pfd[0].revents & POLLIN) {
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            int cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
            bool trusted = ntohl(peer.sin_addr.s_addr) == 0x7F000002;  // 127.0.0.2
            uint8_t s = cfd >= 0 ? smart_session_open(&core, trusted) : SMART_NO_SESSION;
            if (s == SMART_NO_SESSION) {
                if (cfd >= 0)
                    close(cfd);
            } else {
                fds[s] = cfd;
            }
        }
        for (int i = 1; i < n; i++) {
            if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            int s = map[i];
            uint8_t buf[512];
            if (fds[s] < 0)  // the core dropped it while handling another session
                continue;
            ssize_t got = recv(fds[s], buf, sizeof(buf), 0);
            if (got <= 0) {
                smart_session_close(&core, (uint8_t)s);
                close(fds[s]);
                fds[s] = -1;
            } else {
                smart_session_feed(&core, (uint8_t)s, buf, (size_t)got);
            }
        }
        smart_poll(&core);
    }
}
