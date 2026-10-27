// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 siakinnik
// smart-core: portable device protocol core.
//
// Pure C99, no malloc, no OS, no platform headers. Everything platform
// specific (time, sending bytes, persistent storage) comes through
// smart_port_t, implemented by the device project. See PROTOCOL.md.
//
// Not thread-safe: call every smart_* function from one task, or guard them
// with one recursive mutex (on_change runs inside smart_session_feed and may
// call smart_set_*).
//
// Security: a session on a trusted (physical) transport speaks plain
// packets. Every other session must complete a Noise handshake with a
// paired host first; see PROTOCOL.md, Security.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "smart_config.h"
#include "smart_noise.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SMART_PROTO_VERSION 2

// ---------- property types and flags (wire values, see PROTOCOL.md) ----------
typedef enum {
    SMART_T_BOOL = 1,
    SMART_T_U8 = 2,
    SMART_T_U16 = 3,
    SMART_T_I32 = 4,
    SMART_T_ENUM = 5,
    SMART_T_RGB = 6,
    SMART_T_STR = 7,
    SMART_T_ACTION = 8,
} smart_type_t;

#define SMART_F_READ    0x01
#define SMART_F_WRITE   0x02
#define SMART_F_PERSIST 0x04  // saved through the port, restored by smart_load()
#define SMART_F_SECRET  0x08  // never sent back
#define SMART_F_LOCAL   0x10  // only over a trusted (physical) transport
#define SMART_F_RW      (SMART_F_READ | SMART_F_WRITE)

#define SMART_PROP_NONE 0xFF  // "no property" / "all properties"
#define SMART_NO_SESSION 0xFF

typedef struct {
    uint8_t r, g, b;
} smart_rgb_t;

// ---------- platform port ----------
typedef struct {
    void *ctx;
    // monotonic milliseconds
    uint32_t (*millis)(void *ctx);
    // send one encoded packet to a session; return 0 on success
    int (*send)(void *ctx, uint8_t session, const uint8_t *data, size_t len);
    // persistent storage by key ("p" + 8 hex digits, derived from the property name);
    // read returns the number of bytes read, or <0 if there is nothing stored.
    // Both may be NULL if the device persists nothing.
    int (*store_read)(void *ctx, const char *key, void *buf, size_t cap);
    int (*store_write)(void *ctx, const char *key, const void *data, size_t len);
    // `len` cryptographically secure random bytes (hardware RNG). Required
    // for secure sessions: without it the device has no key and refuses them.
    void (*random)(void *ctx, uint8_t *buf, size_t len);
    // Drop the transport behind an untrusted session the core gave up on
    // (failed handshake, unpaired host). The session is already closed.
    void (*close)(void *ctx, uint8_t session);

    // Firmware updates (all optional; without them the device refuses OTA).
    // The core checks the signature, the model and the hash; the port only
    // writes. Bytes arrive in order, from offset 0 to the image size, then
    // the manifest right after the image. Return 0 on success.
    int (*ota_begin)(void *ctx, uint32_t total_size);  // image + manifest
    int (*ota_write)(void *ctx, uint32_t offset, const uint8_t *data, size_t len);
    // ok: everything is written and verified, make it the next boot image
    // (the device reboots when it likes, e.g. right after the ACK has left).
    // !ok: throw the partial image away.
    int (*ota_finish)(void *ctx, bool ok);
} smart_port_t;

// ---------- signed firmware images ----------
// A signed image is the firmware followed by this manifest (little-endian):
//   magic "SMARTFW1" (8) | model_id (2) | reserved (2) | security_version (4)
//   | image size (4) | version string, NUL-padded (32) | SHA-512 of the image (64)
//   | signer Ed25519 public key (32) | Ed25519 signature of all of the above (64)
#define SMART_MANIFEST_LEN 212

typedef struct {
    uint16_t model_id;
    uint32_t security_version;
    uint32_t image_size;
    char version[33];
    uint8_t hash[64];
    uint8_t signer[32];
} smart_manifest_t;

// Parse a manifest and check its signature against the key inside it.
// Doesn't say whether that key is trusted: compare `signer` for that.
bool smart_manifest_parse(const uint8_t raw[SMART_MANIFEST_LEN], smart_manifest_t *out);

// Streaming SHA-512 (images are hashed as they arrive).
typedef struct {
    uint64_t opaque[28];
} smart_hash_t;
void smart_hash_init(smart_hash_t *h);
void smart_hash_update(smart_hash_t *h, const uint8_t *data, size_t len);
void smart_hash_final(smart_hash_t *h, uint8_t out[64]);

// ---------- core instance ----------
typedef struct smart_core smart_core_t;

// Called after a host changed properties (not for changes made with
// smart_set_*). `ids` lists every property the SET touched, in order.
typedef void (*smart_change_cb)(smart_core_t *core, const uint8_t *ids, uint8_t count, void *user);

// Pairing window events, for the device to show (blink, sound, ...) and to
// switch commissioning transports (BLE) on and off. Every OPENED ends with
// exactly one of CONFLICT, TIMEOUT or CLOSED.
typedef enum {
    SMART_PAIRING_OPENED,    // smart_pairing_open(): waiting for a new host
    SMART_PAIRING_PAIRED,    // a new host was paired (over the window, or PAIR on a trusted session)
    SMART_PAIRING_CONFLICT,  // two new hosts in one window: both refused, window over
    SMART_PAIRING_TIMEOUT,   // the window ran out with nobody paired
    SMART_PAIRING_CLOSED,    // the window is over after a pairing (or smart_pairing_close())
} smart_pairing_event_t;

typedef void (*smart_pairing_cb)(smart_core_t *core, smart_pairing_event_t event, void *user);

typedef struct {
    smart_type_t type;
    uint8_t flags;
    const char *name;
    union {
        bool b;
        uint8_t u8;
        uint16_t u16;
        int32_t i32;
        smart_rgb_t rgb;
        struct {
            char *buf;      // caller-owned, cap + 1 bytes
            uint8_t len;
        } str;
    } v;
    union {
        struct { int32_t min, max; } range;
        struct { const char *const *options; uint8_t count; } en;
        uint8_t str_cap;
    } meta;
} smart_prop_t;

typedef struct {
    uint8_t buf[SMART_MAX_PACKET];
    uint16_t len;
    bool open;
    bool trusted;
    bool overflow;
#if SMART_ENABLE_SECURE
    uint8_t sec;           // handshake progress of an untrusted session
    uint32_t opened_at;
    uint8_t peer[32];      // the host's static key, once the handshake is done
    noise_cipher_t tx, rx;
    noise_hs_t hs;         // only during the handshake
#endif
} smart_session_t;

struct smart_core {
    const smart_port_t *port;
    const char *device_id;
    uint16_t model_id;
    const char *model;
    const char *firmware;
    smart_change_cb on_change;
    void *user;

    smart_prop_t props[SMART_MAX_PROPS];
    uint8_t prop_count;
    smart_session_t sessions[SMART_MAX_SESSIONS];

    uint32_t dirty_mask[(SMART_MAX_PROPS + 31) / 32];  // PERSIST props waiting to be saved
    uint32_t dirty_at;

#if SMART_ENABLE_SECURE
    smart_pairing_cb on_pairing;
    bool has_key;
    uint8_t secret_key[32], public_key[32];  // the device's static X25519 key pair
    uint8_t paired[SMART_MAX_PAIRED][32];    // static keys of the paired hosts
    uint8_t paired_count;
    struct {
        uint8_t state;
        uint32_t until;
        uint8_t key[32];  // the host paired in this window: may set LOCAL properties until it ends
    } pairing;
    uint8_t tx_sec[SMART_MAX_RAW];
#endif

#if SMART_ENABLE_OTA
    const uint8_t *ota_key;
    uint32_t security_version;
    struct {
        bool active;
        uint8_t session;     // only the session that started it may continue it
        uint32_t size, offset;
        smart_hash_t hash;
        uint8_t manifest[SMART_MANIFEST_LEN];
    } ota;
#endif

    // transmit buffers: TYPE SEQ PAYLOAD CRC, and its COBS form wrapped in zeros
    uint8_t tx_raw[SMART_MAX_RAW];
    uint8_t tx_enc[SMART_MAX_PACKET + 2];
};

typedef struct {
    const smart_port_t *port;
    const char *device_id;  // e.g. MAC "8C:D0:B2:A8:62:B2"
    uint16_t model_id;      // number from the siakinnik-home model database
    const char *model;      // e.g. "lumenc3"
    const char *firmware;   // e.g. "2.0.0"
    smart_change_cb on_change;
    void *user;
    smart_pairing_cb on_pairing;  // may be NULL
    // OTA: the Ed25519 public key update images must be signed with (32
    // bytes; NULL = no updates over the protocol), and this firmware's
    // security version: images with a lower one are refused, so an update
    // can't bring back a version with a known hole.
    const uint8_t *ota_key;
    uint32_t security_version;
} smart_config_t;

void smart_init(smart_core_t *core, const smart_config_t *cfg);

// ---------- property registration (before smart_load / sessions) ----------
// Each returns the property id, or SMART_PROP_NONE if the table is full.
uint8_t smart_prop_bool(smart_core_t *c, const char *name, uint8_t flags, bool initial);
uint8_t smart_prop_u8(smart_core_t *c, const char *name, uint8_t flags, uint8_t min, uint8_t max, uint8_t initial);
uint8_t smart_prop_u16(smart_core_t *c, const char *name, uint8_t flags, uint16_t min, uint16_t max, uint16_t initial);
uint8_t smart_prop_i32(smart_core_t *c, const char *name, uint8_t flags, int32_t min, int32_t max, int32_t initial);
uint8_t smart_prop_enum(smart_core_t *c, const char *name, uint8_t flags, const char *const *options, uint8_t count, uint8_t initial);
uint8_t smart_prop_rgb(smart_core_t *c, const char *name, uint8_t flags, smart_rgb_t initial);
// `buf` must hold cap + 1 bytes; it stays owned by the caller and is kept NUL-terminated.
// Keep cap well below SMART_MAX_PAYLOAD: a value has to fit in one packet.
uint8_t smart_prop_str(smart_core_t *c, const char *name, uint8_t flags, char *buf, uint8_t cap);
uint8_t smart_prop_action(smart_core_t *c, const char *name, uint8_t flags);

// Restore PERSIST properties, the device key and the paired hosts from
// storage; creates the device key on the first boot. Call once after registration.
void smart_load(smart_core_t *c);

// ---------- values ----------
bool smart_get_bool(const smart_core_t *c, uint8_t id);
uint8_t smart_get_u8(const smart_core_t *c, uint8_t id);   // also enums
uint16_t smart_get_u16(const smart_core_t *c, uint8_t id);
int32_t smart_get_i32(const smart_core_t *c, uint8_t id);
smart_rgb_t smart_get_rgb(const smart_core_t *c, uint8_t id);
const char *smart_get_str(const smart_core_t *c, uint8_t id);

// Local changes: validated like a host SET; sends EVENT to every session
// when the value actually changes. Return false if the value is invalid.
bool smart_set_bool(smart_core_t *c, uint8_t id, bool v);
bool smart_set_u8(smart_core_t *c, uint8_t id, uint8_t v);
bool smart_set_u16(smart_core_t *c, uint8_t id, uint16_t v);
bool smart_set_i32(smart_core_t *c, uint8_t id, int32_t v);
bool smart_set_rgb(smart_core_t *c, uint8_t id, smart_rgb_t v);
bool smart_set_str(smart_core_t *c, uint8_t id, const char *v);

// ---------- sessions (one per connection / serial port) ----------
// `trusted` = physical transport (USB, a wire only you can reach): plain
// packets, LOCAL properties allowed, pairing allowed. Anything else must
// complete the handshake as a paired host before it can do anything.
uint8_t smart_session_open(smart_core_t *c, bool trusted);
void smart_session_close(smart_core_t *c, uint8_t session);
void smart_session_feed(smart_core_t *c, uint8_t session, const uint8_t *data, size_t len);
// Trusted, or an untrusted session whose handshake succeeded. Ports use it to
// pick which connection to drop when they run out: never an authenticated one.
bool smart_session_authenticated(const smart_core_t *c, uint8_t session);

// ---------- pairing ----------
// Open the pairing window for `ms` milliseconds: the first new host that
// completes the handshake is paired. Call on a physical action (a button,
// power-cycling the device a few times): it counts as the owner's consent,
// so until the window ends that host may also set LOCAL properties (Wi-Fi)
// over its untrusted link, e.g. to commission the device over BLE.
// One new host per window: a second one is a conflict and undoes both.
void smart_pairing_open(smart_core_t *c, uint32_t ms);
void smart_pairing_close(smart_core_t *c);
bool smart_pairing_is_open(const smart_core_t *c);
// Forget every paired host and drop their sessions (factory reset).
void smart_unpair_all(smart_core_t *c);
uint8_t smart_paired_count(const smart_core_t *c);
// The device's static public key (32 bytes), or NULL before smart_load().
const uint8_t *smart_public_key(const smart_core_t *c);

// Call regularly (every loop): saves PERSIST properties after
// SMART_PERSIST_DELAY_MS without changes, closes stalled handshakes and the
// pairing window when it runs out.
void smart_poll(smart_core_t *c);
// Save pending PERSIST properties right away (e.g. before a reboot).
void smart_flush(smart_core_t *c);

// ---------- helpers, exposed for tests and host tools ----------
uint16_t smart_crc16(const uint8_t *data, size_t len);
// COBS. Return the output length, or 0 on error (output too small / bad input).
size_t smart_cobs_encode(const uint8_t *in, size_t len, uint8_t *out, size_t cap);
size_t smart_cobs_decode(const uint8_t *in, size_t len, uint8_t *out, size_t cap);

#ifdef __cplusplus
}
#endif
