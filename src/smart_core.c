// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 siakinnik
// Properties, sessions and message handling. See PROTOCOL.md.
#include "smart_core.h"

#include <string.h>

enum {
    MSG_HELLO = 0x01,
    MSG_DESCRIBE = 0x02,
    MSG_GET = 0x03,
    MSG_SET = 0x04,
    MSG_PING = 0x05,
    MSG_PAIR = 0x06,
    MSG_UNPAIR = 0x07,
    MSG_INFO = 0x81,
    MSG_PROP = 0x82,
    MSG_VALUES = 0x83,
    MSG_ACK = 0x84,
    MSG_EVENT = 0x85,
    MSG_PONG = 0x86,
    MSG_ERROR = 0xEE,
};

enum {
    ERR_OK = 0,
    ERR_UNKNOWN_TYPE = 1,
    ERR_BAD_LENGTH = 2,
    ERR_UNKNOWN_PROP = 3,
    ERR_BAD_VALUE = 4,
    ERR_READ_ONLY = 5,
    ERR_FORBIDDEN = 6,
    ERR_BAD_PROTO = 7,
    ERR_PAIRING_FULL = 8,
};

#if SMART_ENABLE_SECURE
// Frame kinds on an untrusted session (first byte of the frame body)
enum {
    K_HS1 = 0xA1,     // host -> device: Noise XX message 1
    K_HS2 = 0xA2,     // device -> host: message 2
    K_HS3 = 0xA3,     // host -> device: message 3
    K_DATA = 0xA4,    // encrypted TYPE SEQ PAYLOAD
    K_REJECT = 0xA5,  // device -> host, plain: reason, then the device hangs up
};

enum {
    REJ_NOT_PAIRED = 1,
    REJ_CONFLICT = 2,
    REJ_FULL = 3,
    REJ_HANDSHAKE = 4,
    REJ_TIMEOUT = 5,
};

enum { SEC_WAIT1, SEC_WAIT3, SEC_READY };
enum { PAIR_CLOSED, PAIR_OPEN, PAIR_CLAIMED };  // CLAIMED: a host paired, the window runs on

// Binds the handshake to this protocol: a Noise session of another
// application with the same keys can't be replayed here.
static const uint8_t PROLOGUE[] = { 's', 'm', 'a', 'r', 't', '-', 'c', 'o', 'r', 'e', '/', '2' };

#define KEY_STORE_SECRET "sk"
#define KEY_STORE_HOSTS "hosts"
#endif


// ---------- byte writer / reader ----------
typedef struct {
    uint8_t *p;
    size_t len, cap;
    bool err;
} wbuf_t;

static void w_u8(wbuf_t *w, uint8_t v)
{
    if (w->len >= w->cap) {
        w->err = true;
        return;
    }
    w->p[w->len++] = v;
}
static void w_u16(wbuf_t *w, uint16_t v) { w_u8(w, (uint8_t)v); w_u8(w, (uint8_t)(v >> 8)); }
static void w_i32(wbuf_t *w, int32_t v)
{
    uint32_t u = (uint32_t)v;
    for (int i = 0; i < 4; i++)
        w_u8(w, (uint8_t)(u >> (8 * i)));
}
static void w_bytes(wbuf_t *w, const void *data, size_t len)
{
    if (w->len + len > w->cap) {
        w->err = true;
        return;
    }
    memcpy(w->p + w->len, data, len);
    w->len += len;
}
static void w_str(wbuf_t *w, const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n > 255)
        n = 255;
    w_u8(w, (uint8_t)n);
    w_bytes(w, s, n);
}

typedef struct {
    const uint8_t *p;
    size_t len, pos;
} rbuf_t;

static bool r_u8(rbuf_t *r, uint8_t *v)
{
    if (r->pos >= r->len)
        return false;
    *v = r->p[r->pos++];
    return true;
}
static bool r_take(rbuf_t *r, size_t n, const uint8_t **out)
{
    if (r->len - r->pos < n)
        return false;
    *out = r->p + r->pos;
    r->pos += n;
    return true;
}

// ---------- helpers ----------
// Storage key for a property: "p" + FNV-1a of its name in hex. Short enough
// for any key-value store (ESP32 NVS allows 15 chars) whatever the name length.
static void persist_key(const char *name, char key[10])
{
    static const char hex[] = "0123456789abcdef";
    uint32_t h = 2166136261u;
    for (; *name; name++)
        h = (h ^ (uint8_t)*name) * 16777619u;
    key[0] = 'p';
    for (int i = 0; i < 8; i++)
        key[1 + i] = hex[(h >> (28 - 4 * i)) & 0xF];
    key[9] = 0;
}

static uint32_t now_ms(smart_core_t *c) { return c->port && c->port->millis ? c->port->millis(c->port->ctx) : 0; }

static smart_prop_t *prop(smart_core_t *c, uint8_t id) { return id < c->prop_count ? &c->props[id] : NULL; }
static const smart_prop_t *cprop(const smart_core_t *c, uint8_t id) { return id < c->prop_count ? &c->props[id] : NULL; }

// may this session see the property's value at all? (`trusted` = LOCAL allowed)
static bool visible(const smart_prop_t *p, bool trusted)
{
    if (!(p->flags & SMART_F_READ) || (p->flags & SMART_F_SECRET))
        return false;
    if ((p->flags & SMART_F_LOCAL) && !trusted)
        return false;
    return p->type != SMART_T_ACTION;
}

static void mark_dirty(smart_core_t *c, uint8_t id)
{
    if (!(c->props[id].flags & SMART_F_PERSIST))
        return;
    c->dirty_mask[id / 32] |= 1UL << (id % 32);
    c->dirty_at = now_ms(c);
}

static void encode_value(wbuf_t *w, const smart_prop_t *p)
{
    switch (p->type) {
    case SMART_T_BOOL: w_u8(w, p->v.b ? 1 : 0); break;
    case SMART_T_U8:
    case SMART_T_ENUM: w_u8(w, p->v.u8); break;
    case SMART_T_U16: w_u16(w, p->v.u16); break;
    case SMART_T_I32: w_i32(w, p->v.i32); break;
    case SMART_T_RGB: w_u8(w, p->v.rgb.r); w_u8(w, p->v.rgb.g); w_u8(w, p->v.rgb.b); break;
    case SMART_T_STR: w_u8(w, p->v.str.len); w_bytes(w, p->v.str.buf, p->v.str.len); break;
    case SMART_T_ACTION: break;
    }
}

// A value parsed off the wire, not yet applied.
typedef struct {
    int32_t num;  // bool / u8 / u16 / i32 / enum
    smart_rgb_t rgb;
    const uint8_t *str;
    uint8_t str_len;
} value_t;

// Read one value of p's type and check it. Returns an ERR_* code.
static int parse_value(rbuf_t *r, const smart_prop_t *p, value_t *v)
{
    const uint8_t *b;
    switch (p->type) {
    case SMART_T_BOOL:
        if (!r_take(r, 1, &b)) return ERR_BAD_LENGTH;
        if (b[0] > 1) return ERR_BAD_VALUE;
        v->num = b[0];
        return ERR_OK;
    case SMART_T_U8:
    case SMART_T_ENUM:
        if (!r_take(r, 1, &b)) return ERR_BAD_LENGTH;
        v->num = b[0];
        break;
    case SMART_T_U16:
        if (!r_take(r, 2, &b)) return ERR_BAD_LENGTH;
        v->num = (int32_t)(b[0] | (b[1] << 8));
        break;
    case SMART_T_I32:
        if (!r_take(r, 4, &b)) return ERR_BAD_LENGTH;
        v->num = (int32_t)((uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24));
        break;
    case SMART_T_RGB:
        if (!r_take(r, 3, &b)) return ERR_BAD_LENGTH;
        v->rgb.r = b[0]; v->rgb.g = b[1]; v->rgb.b = b[2];
        return ERR_OK;
    case SMART_T_STR:
        if (!r_u8(r, &v->str_len)) return ERR_BAD_LENGTH;
        if (!r_take(r, v->str_len, &v->str)) return ERR_BAD_LENGTH;
        if (v->str_len > p->meta.str_cap || memchr(v->str, 0, v->str_len)) return ERR_BAD_VALUE;
        return ERR_OK;
    case SMART_T_ACTION:
        return ERR_OK;
    }
    if (p->type == SMART_T_ENUM)
        return v->num < p->meta.en.count ? ERR_OK : ERR_BAD_VALUE;
    return (v->num >= p->meta.range.min && v->num <= p->meta.range.max) ? ERR_OK : ERR_BAD_VALUE;
}

// Store a checked value. Returns true if it changed (actions always "change").
static bool apply_value(smart_prop_t *p, const value_t *v)
{
    switch (p->type) {
    case SMART_T_BOOL:
        if (p->v.b == (v->num != 0)) return false;
        p->v.b = v->num != 0;
        return true;
    case SMART_T_U8:
    case SMART_T_ENUM:
        if (p->v.u8 == (uint8_t)v->num) return false;
        p->v.u8 = (uint8_t)v->num;
        return true;
    case SMART_T_U16:
        if (p->v.u16 == (uint16_t)v->num) return false;
        p->v.u16 = (uint16_t)v->num;
        return true;
    case SMART_T_I32:
        if (p->v.i32 == v->num) return false;
        p->v.i32 = v->num;
        return true;
    case SMART_T_RGB:
        if (!memcmp(&p->v.rgb, &v->rgb, sizeof(v->rgb))) return false;
        p->v.rgb = v->rgb;
        return true;
    case SMART_T_STR:
        if (p->v.str.len == v->str_len && !memcmp(p->v.str.buf, v->str, v->str_len)) return false;
        memcpy(p->v.str.buf, v->str, v->str_len);
        p->v.str.buf[v->str_len] = 0;
        p->v.str.len = v->str_len;
        return true;
    case SMART_T_ACTION:
        return true;
    }
    return false;
}

// ---------- sending ----------
static wbuf_t begin_packet(smart_core_t *c, uint8_t type, uint8_t seq)
{
    c->tx_raw[0] = type;
    c->tx_raw[1] = seq;
    wbuf_t w = { c->tx_raw + 2, 0, SMART_MAX_PAYLOAD, false };
    return w;
}

// COBS-encode a frame body, wrap it in zeros, send it
static void send_body(smart_core_t *c, uint8_t session, const uint8_t *body, size_t len)
{
    if (!c->port || !c->port->send)
        return;
    c->tx_enc[0] = 0;
    size_t n = smart_cobs_encode(body, len, c->tx_enc + 1, sizeof(c->tx_enc) - 2);
    if (!n)
        return;
    c->tx_enc[n + 1] = 0;
    c->port->send(c->port->ctx, session, c->tx_enc, n + 2);
}

static bool plain_session(const smart_core_t *c, uint8_t session)
{
#if SMART_ENABLE_SECURE
    return c->sessions[session].trusted;
#else
    (void)c;
    (void)session;
    return true;
#endif
}

static void finish_packet(smart_core_t *c, uint8_t session, const wbuf_t *w)
{
    if (w->err)
        return;
    size_t raw_len = 2 + w->len;
    if (plain_session(c, session)) {
        uint16_t crc = smart_crc16(c->tx_raw, raw_len);
        c->tx_raw[raw_len++] = (uint8_t)crc;
        c->tx_raw[raw_len++] = (uint8_t)(crc >> 8);
        send_body(c, session, c->tx_raw, raw_len);
        return;
    }
#if SMART_ENABLE_SECURE
    smart_session_t *ss = &c->sessions[session];
    if (ss->sec != SEC_READY)
        return;  // nothing goes out before the handshake
    c->tx_sec[0] = K_DATA;
    noise_encrypt(&ss->tx, c->tx_raw, raw_len, c->tx_sec + 1);
    send_body(c, session, c->tx_sec, 1 + raw_len + NOISE_TAG_LEN);
#endif
}

static void send_simple(smart_core_t *c, uint8_t session, uint8_t type, uint8_t seq)
{
    wbuf_t w = begin_packet(c, type, seq);
    finish_packet(c, session, &w);
}

static void send_error(smart_core_t *c, uint8_t session, uint8_t seq, uint8_t code, uint8_t id)
{
    wbuf_t w = begin_packet(c, MSG_ERROR, seq);
    w_u8(&w, code);
    w_u8(&w, id);
    finish_packet(c, session, &w);
}

// Send the values of `ids` that this session may see, split into as many
// packets as needed. Sends nothing if none are visible.
static bool local_ok(const smart_core_t *c, uint8_t session);

static void send_values(smart_core_t *c, uint8_t session, uint8_t type, uint8_t seq, const uint8_t *ids, uint8_t count)
{
    bool trusted = local_ok(c, session);
    wbuf_t w = begin_packet(c, type, seq);
    bool any = false;

    for (uint8_t i = 0; i < count; i++) {
        const smart_prop_t *p = &c->props[ids[i]];
        if (!visible(p, trusted))
            continue;
        size_t mark = w.len;
        w_u8(&w, ids[i]);
        encode_value(&w, p);
        if (w.err) {  // packet full: send what we have, start a new one with this value
            w.len = mark;
            w.err = false;
            finish_packet(c, session, &w);
            w = begin_packet(c, type, seq);
            w_u8(&w, ids[i]);
            encode_value(&w, p);
        }
        any = true;
    }
    if (any)
        finish_packet(c, session, &w);
}

static void broadcast_event(smart_core_t *c, const uint8_t *ids, uint8_t count)
{
    if (!count)
        return;
    for (uint8_t s = 0; s < SMART_MAX_SESSIONS; s++)
        if (smart_session_authenticated(c, s))
            send_values(c, s, MSG_EVENT, 0, ids, count);
}

// ---------- message handlers ----------
static void on_hello(smart_core_t *c, uint8_t s, uint8_t seq, rbuf_t *r)
{
    uint8_t proto;
    if (!r_u8(r, &proto)) {
        send_error(c, s, seq, ERR_BAD_LENGTH, SMART_PROP_NONE);
        return;
    }
    if (proto == 0) {  // a newer host talks down to our version; 0 is never valid
        send_error(c, s, seq, ERR_BAD_PROTO, SMART_PROP_NONE);
        return;
    }
    wbuf_t w = begin_packet(c, MSG_INFO, seq);
    w_u8(&w, SMART_PROTO_VERSION);
    w_u8(&w, c->prop_count);
    w_u16(&w, c->model_id);
    w_str(&w, c->device_id);
    w_str(&w, c->model);
    w_str(&w, c->firmware);
#if SMART_ENABLE_SECURE
    if (c->has_key)
        w_bytes(&w, c->public_key, 32);  // hosts pin it when pairing over USB
#endif
    finish_packet(c, s, &w);
}

#if SMART_ENABLE_DESCRIBE
static void on_describe(smart_core_t *c, uint8_t s, uint8_t seq, rbuf_t *r)
{
    uint8_t id;
    if (!r_u8(r, &id)) {
        send_error(c, s, seq, ERR_BAD_LENGTH, SMART_PROP_NONE);
        return;
    }
    const smart_prop_t *p = cprop(c, id);
    if (!p) {
        send_error(c, s, seq, ERR_UNKNOWN_PROP, id);
        return;
    }
    wbuf_t w = begin_packet(c, MSG_PROP, seq);
    w_u8(&w, id);
    w_u8(&w, (uint8_t)p->type);
    w_u8(&w, p->flags);
    w_str(&w, p->name);
    switch (p->type) {
    case SMART_T_U8: w_u8(&w, (uint8_t)p->meta.range.min); w_u8(&w, (uint8_t)p->meta.range.max); break;
    case SMART_T_U16: w_u16(&w, (uint16_t)p->meta.range.min); w_u16(&w, (uint16_t)p->meta.range.max); break;
    case SMART_T_I32: w_i32(&w, p->meta.range.min); w_i32(&w, p->meta.range.max); break;
    case SMART_T_ENUM:
        w_u8(&w, p->meta.en.count);
        for (uint8_t i = 0; i < p->meta.en.count; i++)
            w_str(&w, p->meta.en.options[i]);
        break;
    case SMART_T_STR: w_u8(&w, p->meta.str_cap); break;
    default: break;
    }
    if (w.err) {
        send_error(c, s, seq, ERR_BAD_LENGTH, id);
        return;
    }
    finish_packet(c, s, &w);
}

#endif

static void on_get(smart_core_t *c, uint8_t s, uint8_t seq, rbuf_t *r)
{
    uint8_t id;
    if (!r_u8(r, &id)) {
        send_error(c, s, seq, ERR_BAD_LENGTH, SMART_PROP_NONE);
        return;
    }
    if (id == SMART_PROP_NONE) {
        uint8_t ids[SMART_MAX_PROPS];
        for (uint8_t i = 0; i < c->prop_count; i++)
            ids[i] = i;
        // any number of VALUES packets (maybe none), then ACK marks the end
        send_values(c, s, MSG_VALUES, seq, ids, c->prop_count);
        send_simple(c, s, MSG_ACK, seq);
        return;
    }
    const smart_prop_t *p = cprop(c, id);
    if (!p) {
        send_error(c, s, seq, ERR_UNKNOWN_PROP, id);
        return;
    }
    if (!visible(p, local_ok(c, s))) {
        send_error(c, s, seq, ERR_FORBIDDEN, id);
        return;
    }
    send_values(c, s, MSG_VALUES, seq, &id, 1);
}

static void on_set(smart_core_t *c, uint8_t s, uint8_t seq, rbuf_t *r)
{
    bool trusted = local_ok(c, s);
    if (r->len == 0) {
        send_error(c, s, seq, ERR_BAD_LENGTH, SMART_PROP_NONE);
        return;
    }

    // pass 1: validate everything, change nothing
    rbuf_t check = *r;
    while (check.pos < check.len) {
        uint8_t id;
        value_t v;
        r_u8(&check, &id);
        const smart_prop_t *p = cprop(c, id);
        if (!p) { send_error(c, s, seq, ERR_UNKNOWN_PROP, id); return; }
        if (!(p->flags & SMART_F_WRITE)) { send_error(c, s, seq, ERR_READ_ONLY, id); return; }
        if ((p->flags & SMART_F_LOCAL) && !trusted) { send_error(c, s, seq, ERR_FORBIDDEN, id); return; }
        int err = parse_value(&check, p, &v);
        if (err) { send_error(c, s, seq, (uint8_t)err, id); return; }
    }

    // pass 2: apply
    uint8_t touched[SMART_MAX_PROPS], changed[SMART_MAX_PROPS];
    uint8_t n_touched = 0, n_changed = 0;
    while (r->pos < r->len) {
        uint8_t id;
        value_t v;
        r_u8(r, &id);
        smart_prop_t *p = prop(c, id);
        parse_value(r, p, &v);
        bool did_change = apply_value(p, &v);

        bool seen = false;
        for (uint8_t i = 0; i < n_touched; i++)
            seen |= touched[i] == id;
        if (!seen)
            touched[n_touched++] = id;
        if (did_change && p->type != SMART_T_ACTION) {
            seen = false;
            for (uint8_t i = 0; i < n_changed; i++)
                seen |= changed[i] == id;
            if (!seen)
                changed[n_changed++] = id;
            mark_dirty(c, id);
        }
    }

    send_simple(c, s, MSG_ACK, seq);
    if (c->on_change)
        c->on_change(c, touched, n_touched, c->user);
    broadcast_event(c, changed, n_changed);
}

#if SMART_ENABLE_SECURE
static void on_pair(smart_core_t *c, uint8_t s, uint8_t seq, rbuf_t *r);
static void on_unpair(smart_core_t *c, uint8_t s, uint8_t seq, rbuf_t *r);
#endif

// TYPE SEQ PAYLOAD, already authenticated (CRC or AEAD)
static void handle_message(smart_core_t *c, uint8_t s, const uint8_t *raw, size_t len)
{
    if (len < 2)
        return;
    uint8_t type = raw[0], seq = raw[1];
    rbuf_t r = { raw + 2, len - 2, 0 };
    switch (type) {
    case MSG_HELLO: on_hello(c, s, seq, &r); break;
#if SMART_ENABLE_DESCRIBE
    case MSG_DESCRIBE: on_describe(c, s, seq, &r); break;
#endif
    case MSG_GET: on_get(c, s, seq, &r); break;
    case MSG_SET: on_set(c, s, seq, &r); break;
    case MSG_PING: send_simple(c, s, MSG_PONG, seq); break;
#if SMART_ENABLE_SECURE
    case MSG_PAIR: on_pair(c, s, seq, &r); break;
    case MSG_UNPAIR: on_unpair(c, s, seq, &r); break;
#endif
    default: send_error(c, s, seq, ERR_UNKNOWN_TYPE, SMART_PROP_NONE); break;
    }
}

// a plain frame: TYPE SEQ PAYLOAD CRC16
static void handle_plain(smart_core_t *c, uint8_t s, const uint8_t *raw, size_t len)
{
    if (len < 4)
        return;
    uint16_t crc = (uint16_t)(raw[len - 2] | (raw[len - 1] << 8));
    if (smart_crc16(raw, len - 2) != crc)
        return;  // corrupted or log noise: no reply
    handle_message(c, s, raw, len - 2);
}

// ---------- security: keys, paired hosts, handshake ----------
#if SMART_ENABLE_SECURE
static void random_bytes(smart_core_t *c, uint8_t *buf, size_t len)
{
    c->port->random(c->port->ctx, buf, len);
}

static bool can_secure(const smart_core_t *c)
{
    return c->has_key && c->port && c->port->random;
}

static void emit_pairing(smart_core_t *c, smart_pairing_event_t ev)
{
    if (c->on_pairing)
        c->on_pairing(c, ev, c->user);
}

static bool same_key(const uint8_t a[32], const uint8_t b[32])
{
    return noise_equal32(a, b);
}

static int find_paired(const smart_core_t *c, const uint8_t key[32])
{
    for (uint8_t i = 0; i < c->paired_count; i++)
        if (same_key(c->paired[i], key))
            return i;
    return -1;
}

static void save_paired(smart_core_t *c)
{
    if (!c->port || !c->port->store_write)
        return;
    uint8_t blob[1 + SMART_MAX_PAIRED * 32];
    blob[0] = c->paired_count;
    memcpy(blob + 1, c->paired, (size_t)c->paired_count * 32);
    c->port->store_write(c->port->ctx, KEY_STORE_HOSTS, blob, 1 + (size_t)c->paired_count * 32);
}

static bool add_paired(smart_core_t *c, const uint8_t key[32])
{
    if (find_paired(c, key) >= 0)
        return true;
    if (c->paired_count >= SMART_MAX_PAIRED)
        return false;
    memcpy(c->paired[c->paired_count++], key, 32);
    save_paired(c);
    return true;
}

static void wipe_session_secrets(smart_session_t *ss)
{
    noise_wipe(&ss->hs, sizeof(ss->hs));
    noise_wipe(&ss->tx, sizeof(ss->tx));
    noise_wipe(&ss->rx, sizeof(ss->rx));
}

// The core gives up on an untrusted session: forget it, let the port hang up.
static void drop_session(smart_core_t *c, uint8_t s)
{
    smart_session_t *ss = &c->sessions[s];
    if (!ss->open)
        return;
    ss->open = false;
    wipe_session_secrets(ss);
    if (c->port && c->port->close)
        c->port->close(c->port->ctx, s);
}

static void reject(smart_core_t *c, uint8_t s, uint8_t reason)
{
    uint8_t body[2] = { K_REJECT, reason };
    send_body(c, s, body, sizeof(body));
    drop_session(c, s);
}

// Forget a host and drop every secure session it has open.
static void remove_paired(smart_core_t *c, const uint8_t key[32])
{
    uint8_t k[32];
    memcpy(k, key, 32);  // `key` may point into the table we shift
    int i = find_paired(c, k);
    if (i >= 0) {
        memmove(c->paired[i], c->paired[i + 1], (size_t)(c->paired_count - i - 1) * 32);
        c->paired_count--;
        save_paired(c);
    }
    for (uint8_t s = 0; s < SMART_MAX_SESSIONS; s++) {
        smart_session_t *ss = &c->sessions[s];
        if (ss->open && !ss->trusted && ss->sec == SEC_READY && same_key(ss->peer, k))
            drop_session(c, s);
    }
}

// The handshake proved the host holds ss->peer. Is it allowed in?
static void admit(smart_core_t *c, uint8_t s)
{
    smart_session_t *ss = &c->sessions[s];
    if (find_paired(c, ss->peer) >= 0) {
        ss->sec = SEC_READY;
        return;
    }
    switch (c->pairing.state) {
    case PAIR_OPEN:
        if (!add_paired(c, ss->peer)) {
            reject(c, s, REJ_FULL);
            return;
        }
        memcpy(c->pairing.key, ss->peer, 32);
        c->pairing.state = PAIR_CLAIMED;  // the window runs on: conflicts, LOCAL rights
        ss->sec = SEC_READY;
        emit_pairing(c, SMART_PAIRING_PAIRED);
        return;
    case PAIR_CLAIMED:
        // A second new host in the same window: somebody is racing the
        // owner. Trust neither of them.
        c->pairing.state = PAIR_CLOSED;
        reject(c, s, REJ_CONFLICT);
        remove_paired(c, c->pairing.key);
        noise_wipe(c->pairing.key, 32);
        emit_pairing(c, SMART_PAIRING_CONFLICT);
        return;
    default:
        reject(c, s, REJ_NOT_PAIRED);
        return;
    }
}

// One frame body on an untrusted session.
static void handle_secure(smart_core_t *c, uint8_t s, uint8_t *body, size_t len)
{
    smart_session_t *ss = &c->sessions[s];
    if (len < 1)
        return;
    uint8_t kind = body[0], *d = body + 1;
    size_t dl = len - 1;

    switch (ss->sec) {
    case SEC_WAIT1: {
        if (kind != K_HS1 || dl != NOISE_XX_MSG1_LEN(0) || !can_secure(c)) {
            reject(c, s, REJ_HANDSHAKE);
            return;
        }
        uint8_t e[32], out[1 + NOISE_XX_MSG2_LEN(0)];
        random_bytes(c, e, sizeof(e));
        noise_hs_init(&ss->hs, PROLOGUE, sizeof(PROLOGUE), c->secret_key, c->public_key, e);
        noise_wipe(e, sizeof(e));
        noise_xx_read1(&ss->hs, d, dl, NULL);
        out[0] = K_HS2;
        if (!noise_xx_write2(&ss->hs, NULL, 0, out + 1)) {
            reject(c, s, REJ_HANDSHAKE);
            return;
        }
        send_body(c, s, out, sizeof(out));
        ss->sec = SEC_WAIT3;
        return;
    }
    case SEC_WAIT3:
        if (kind != K_HS3 || dl != NOISE_XX_MSG3_LEN(0) ||
            !noise_xx_read3(&ss->hs, d, dl, NULL, &ss->tx, &ss->rx)) {
            reject(c, s, REJ_HANDSHAKE);
            return;
        }
        memcpy(ss->peer, ss->hs.rs, 32);
        noise_wipe(&ss->hs, sizeof(ss->hs));
        admit(c, s);
        return;
    default:
        // A frame that doesn't decrypt breaks the session for good: the
        // nonces are out of step, or somebody is tampering with it.
        if (kind != K_DATA || dl < NOISE_TAG_LEN || !noise_decrypt(&ss->rx, d, dl, d)) {
            drop_session(c, s);
            return;
        }
        handle_message(c, s, d, dl - NOISE_TAG_LEN);
        return;
    }
}

// PAIR: on a trusted session, add a host's key (physical access = consent).
static void on_pair(smart_core_t *c, uint8_t s, uint8_t seq, rbuf_t *r)
{
    const uint8_t *key;
    if (!c->sessions[s].trusted) {
        send_error(c, s, seq, ERR_FORBIDDEN, SMART_PROP_NONE);
        return;
    }
    if (r->len != 32 || !r_take(r, 32, &key)) {
        send_error(c, s, seq, ERR_BAD_LENGTH, SMART_PROP_NONE);
        return;
    }
    bool is_new = find_paired(c, key) < 0;
    if (!add_paired(c, key)) {
        send_error(c, s, seq, ERR_PAIRING_FULL, SMART_PROP_NONE);
        return;
    }
    send_simple(c, s, MSG_ACK, seq);
    if (is_new)
        emit_pairing(c, SMART_PAIRING_PAIRED);
}

// UNPAIR: a trusted session removes any host (or all of them, with no key);
// a secure session may only remove its own host.
static void on_unpair(smart_core_t *c, uint8_t s, uint8_t seq, rbuf_t *r)
{
    smart_session_t *ss = &c->sessions[s];
    const uint8_t *key = NULL;
    if (r->len == 32) {
        r_take(r, 32, &key);
    } else if (r->len != 0 || !ss->trusted) {
        send_error(c, s, seq, ERR_BAD_LENGTH, SMART_PROP_NONE);
        return;
    }
    if (!ss->trusted && !same_key(key, ss->peer)) {
        send_error(c, s, seq, ERR_FORBIDDEN, SMART_PROP_NONE);
        return;
    }
    send_simple(c, s, MSG_ACK, seq);  // before we possibly drop this very session
    if (key)
        remove_paired(c, key);
    else
        smart_unpair_all(c);
}

static void load_keys(smart_core_t *c)
{
    const smart_port_t *p = c->port;
    uint8_t blob[1 + SMART_MAX_PAIRED * 32];
    if (!p)
        return;

    c->has_key = false;
    if (p->store_read && p->store_read(p->ctx, KEY_STORE_SECRET, c->secret_key, 32) == 32) {
        c->has_key = true;
    } else if (p->random) {
        // first boot: create the device's identity
        random_bytes(c, c->secret_key, 32);
        c->has_key = true;
        if (p->store_write)
            p->store_write(p->ctx, KEY_STORE_SECRET, c->secret_key, 32);
    }
    if (c->has_key)
        noise_public_key(c->public_key, c->secret_key);

    c->paired_count = 0;
    int n = p->store_read ? p->store_read(p->ctx, KEY_STORE_HOSTS, blob, sizeof(blob)) : -1;
    if (n >= 1 && blob[0] <= SMART_MAX_PAIRED && n == 1 + blob[0] * 32) {
        c->paired_count = blob[0];
        memcpy(c->paired, blob + 1, (size_t)n - 1);
    }
}

static void poll_security(smart_core_t *c)
{
    uint32_t now = now_ms(c);
    for (uint8_t s = 0; s < SMART_MAX_SESSIONS; s++) {
        smart_session_t *ss = &c->sessions[s];
        if (ss->open && !ss->trusted && ss->sec != SEC_READY &&
            (uint32_t)(now - ss->opened_at) >= SMART_HANDSHAKE_TIMEOUT_MS)
            reject(c, s, REJ_TIMEOUT);
    }
    if (c->pairing.state != PAIR_CLOSED && (int32_t)(now - c->pairing.until) >= 0) {
        bool nobody = c->pairing.state == PAIR_OPEN;
        c->pairing.state = PAIR_CLOSED;
        noise_wipe(c->pairing.key, 32);
        emit_pairing(c, nobody ? SMART_PAIRING_TIMEOUT : SMART_PAIRING_CLOSED);
    }
}
#endif

// May this session use LOCAL properties? A trusted (physical) session, or
// the host paired in the current pairing window, until the window ends.
static bool local_ok(const smart_core_t *c, uint8_t session)
{
    const smart_session_t *ss = &c->sessions[session];
    if (ss->trusted)
        return true;
#if SMART_ENABLE_SECURE
    return ss->sec == SEC_READY && c->pairing.state == PAIR_CLAIMED && noise_equal32(ss->peer, c->pairing.key);
#else
    return false;
#endif
}

// ---------- public API ----------
void smart_init(smart_core_t *c, const smart_config_t *cfg)
{
    memset(c, 0, sizeof(*c));
    c->port = cfg->port;
    c->device_id = cfg->device_id;
    c->model_id = cfg->model_id;
    c->model = cfg->model;
    c->firmware = cfg->firmware;
    c->on_change = cfg->on_change;
    c->user = cfg->user;
#if SMART_ENABLE_SECURE
    c->on_pairing = cfg->on_pairing;
#endif
}

static smart_prop_t *add_prop(smart_core_t *c, const char *name, smart_type_t type, uint8_t flags, uint8_t *id)
{
    if (c->prop_count >= SMART_MAX_PROPS || !name)
        return NULL;
    *id = c->prop_count++;
    smart_prop_t *p = &c->props[*id];
    memset(p, 0, sizeof(*p));
    p->type = type;
    p->flags = flags;
    p->name = name;
    return p;
}

static uint8_t add_number(smart_core_t *c, const char *name, smart_type_t type, uint8_t flags, int32_t min, int32_t max, int32_t initial)
{
    uint8_t id;
    if (min > max || initial < min || initial > max)
        return SMART_PROP_NONE;
    smart_prop_t *p = add_prop(c, name, type, flags, &id);
    if (!p)
        return SMART_PROP_NONE;
    p->meta.range.min = min;
    p->meta.range.max = max;
    value_t v = { .num = initial };
    apply_value(p, &v);
    return id;
}

uint8_t smart_prop_bool(smart_core_t *c, const char *name, uint8_t flags, bool initial)
{
    uint8_t id;
    smart_prop_t *p = add_prop(c, name, SMART_T_BOOL, flags, &id);
    if (!p)
        return SMART_PROP_NONE;
    p->v.b = initial;
    return id;
}

uint8_t smart_prop_u8(smart_core_t *c, const char *name, uint8_t flags, uint8_t min, uint8_t max, uint8_t initial)
{
    return add_number(c, name, SMART_T_U8, flags, min, max, initial);
}

uint8_t smart_prop_u16(smart_core_t *c, const char *name, uint8_t flags, uint16_t min, uint16_t max, uint16_t initial)
{
    return add_number(c, name, SMART_T_U16, flags, min, max, initial);
}

uint8_t smart_prop_i32(smart_core_t *c, const char *name, uint8_t flags, int32_t min, int32_t max, int32_t initial)
{
    return add_number(c, name, SMART_T_I32, flags, min, max, initial);
}

uint8_t smart_prop_enum(smart_core_t *c, const char *name, uint8_t flags, const char *const *options, uint8_t count, uint8_t initial)
{
    uint8_t id;
    if (!options || !count || initial >= count)
        return SMART_PROP_NONE;
    smart_prop_t *p = add_prop(c, name, SMART_T_ENUM, flags, &id);
    if (!p)
        return SMART_PROP_NONE;
    p->meta.en.options = options;
    p->meta.en.count = count;
    p->v.u8 = initial;
    return id;
}

uint8_t smart_prop_rgb(smart_core_t *c, const char *name, uint8_t flags, smart_rgb_t initial)
{
    uint8_t id;
    smart_prop_t *p = add_prop(c, name, SMART_T_RGB, flags, &id);
    if (!p)
        return SMART_PROP_NONE;
    p->v.rgb = initial;
    return id;
}

uint8_t smart_prop_str(smart_core_t *c, const char *name, uint8_t flags, char *buf, uint8_t cap)
{
    uint8_t id;
    if (!buf)
        return SMART_PROP_NONE;
    smart_prop_t *p = add_prop(c, name, SMART_T_STR, flags, &id);
    if (!p)
        return SMART_PROP_NONE;
    p->meta.str_cap = cap;
    p->v.str.buf = buf;
    size_t n = 0;
    while (n < cap && buf[n])
        n++;
    buf[n] = 0;
    p->v.str.len = (uint8_t)n;
    return id;
}

uint8_t smart_prop_action(smart_core_t *c, const char *name, uint8_t flags)
{
    uint8_t id;
    // actions are write-only and never persisted
    smart_prop_t *p = add_prop(c, name, SMART_T_ACTION, (uint8_t)((flags | SMART_F_WRITE) & ~(SMART_F_READ | SMART_F_PERSIST)), &id);
    return p ? id : SMART_PROP_NONE;
}

void smart_load(smart_core_t *c)
{
#if SMART_ENABLE_SECURE
    load_keys(c);
#endif
    if (!c->port || !c->port->store_read)
        return;
    uint8_t buf[256];
    for (uint8_t id = 0; id < c->prop_count; id++) {
        smart_prop_t *p = &c->props[id];
        if (!(p->flags & SMART_F_PERSIST))
            continue;
        char key[10];
        persist_key(p->name, key);
        int n = c->port->store_read(c->port->ctx, key, buf, sizeof(buf));
        if (n <= 0)
            continue;
        rbuf_t r = { buf, (size_t)n, 0 };
        value_t v;
        // stored data is in wire format; anything that no longer fits
        // (range changed in a firmware update) keeps the default
        if (parse_value(&r, p, &v) == ERR_OK && r.pos == r.len)
            apply_value(p, &v);
    }
}

void smart_flush(smart_core_t *c)
{
    bool can_store = c->port && c->port->store_write;
    uint8_t buf[256];
    for (uint8_t id = 0; id < c->prop_count; id++) {
        if (!(c->dirty_mask[id / 32] & (1UL << (id % 32))))
            continue;
        c->dirty_mask[id / 32] &= ~(1UL << (id % 32));
        if (!can_store)
            continue;
        wbuf_t w = { buf, 0, sizeof(buf), false };
        encode_value(&w, &c->props[id]);
        char key[10];
        persist_key(c->props[id].name, key);
        if (!w.err)
            c->port->store_write(c->port->ctx, key, buf, w.len);
    }
}

void smart_poll(smart_core_t *c)
{
#if SMART_ENABLE_SECURE
    poll_security(c);
#endif
    bool dirty = false;
    for (size_t i = 0; i < sizeof(c->dirty_mask) / sizeof(c->dirty_mask[0]); i++)
        dirty |= c->dirty_mask[i] != 0;
    if (dirty && (uint32_t)(now_ms(c) - c->dirty_at) >= SMART_PERSIST_DELAY_MS)
        smart_flush(c);
}

// ---------- local getters / setters ----------
static const smart_prop_t *typed(const smart_core_t *c, uint8_t id, smart_type_t t1, smart_type_t t2)
{
    const smart_prop_t *p = cprop(c, id);
    return (p && (p->type == t1 || p->type == t2)) ? p : NULL;
}

bool smart_get_bool(const smart_core_t *c, uint8_t id)
{
    const smart_prop_t *p = typed(c, id, SMART_T_BOOL, SMART_T_BOOL);
    return p ? p->v.b : false;
}
uint8_t smart_get_u8(const smart_core_t *c, uint8_t id)
{
    const smart_prop_t *p = typed(c, id, SMART_T_U8, SMART_T_ENUM);
    return p ? p->v.u8 : 0;
}
uint16_t smart_get_u16(const smart_core_t *c, uint8_t id)
{
    const smart_prop_t *p = typed(c, id, SMART_T_U16, SMART_T_U16);
    return p ? p->v.u16 : 0;
}
int32_t smart_get_i32(const smart_core_t *c, uint8_t id)
{
    const smart_prop_t *p = typed(c, id, SMART_T_I32, SMART_T_I32);
    return p ? p->v.i32 : 0;
}
smart_rgb_t smart_get_rgb(const smart_core_t *c, uint8_t id)
{
    const smart_prop_t *p = typed(c, id, SMART_T_RGB, SMART_T_RGB);
    smart_rgb_t none = { 0, 0, 0 };
    return p ? p->v.rgb : none;
}
const char *smart_get_str(const smart_core_t *c, uint8_t id)
{
    const smart_prop_t *p = typed(c, id, SMART_T_STR, SMART_T_STR);
    return p ? p->v.str.buf : "";
}

// validate + apply + persist + EVENT, shared by every local setter
static bool local_set(smart_core_t *c, uint8_t id, smart_type_t t1, smart_type_t t2, const uint8_t *wire, size_t len)
{
    smart_prop_t *p = prop(c, id);
    if (!p || (p->type != t1 && p->type != t2))
        return false;
    rbuf_t r = { wire, len, 0 };
    value_t v;
    if (parse_value(&r, p, &v) != ERR_OK)
        return false;
    if (apply_value(p, &v)) {
        mark_dirty(c, id);
        broadcast_event(c, &id, 1);
    }
    return true;
}

bool smart_set_bool(smart_core_t *c, uint8_t id, bool v)
{
    uint8_t b = v ? 1 : 0;
    return local_set(c, id, SMART_T_BOOL, SMART_T_BOOL, &b, 1);
}
bool smart_set_u8(smart_core_t *c, uint8_t id, uint8_t v)
{
    return local_set(c, id, SMART_T_U8, SMART_T_ENUM, &v, 1);
}
bool smart_set_u16(smart_core_t *c, uint8_t id, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
    return local_set(c, id, SMART_T_U16, SMART_T_U16, b, 2);
}
bool smart_set_i32(smart_core_t *c, uint8_t id, int32_t v)
{
    uint32_t u = (uint32_t)v;
    uint8_t b[4] = { (uint8_t)u, (uint8_t)(u >> 8), (uint8_t)(u >> 16), (uint8_t)(u >> 24) };
    return local_set(c, id, SMART_T_I32, SMART_T_I32, b, 4);
}
bool smart_set_rgb(smart_core_t *c, uint8_t id, smart_rgb_t v)
{
    uint8_t b[3] = { v.r, v.g, v.b };
    return local_set(c, id, SMART_T_RGB, SMART_T_RGB, b, 3);
}
bool smart_set_str(smart_core_t *c, uint8_t id, const char *v)
{
    uint8_t b[256];
    size_t n = v ? strlen(v) : 0;
    if (n > 255)
        return false;
    b[0] = (uint8_t)n;
    memcpy(b + 1, v, n);
    return local_set(c, id, SMART_T_STR, SMART_T_STR, b, n + 1);
}

// ---------- sessions ----------
uint8_t smart_session_open(smart_core_t *c, bool trusted)
{
    for (uint8_t s = 0; s < SMART_MAX_SESSIONS; s++) {
        smart_session_t *ss = &c->sessions[s];
        if (!ss->open) {
            ss->open = true;
            ss->trusted = trusted;
            ss->len = 0;
            ss->overflow = false;
#if SMART_ENABLE_SECURE
            ss->sec = SEC_WAIT1;
            ss->opened_at = now_ms(c);
            wipe_session_secrets(ss);
#endif
            return s;
        }
    }
    return SMART_NO_SESSION;
}

void smart_session_close(smart_core_t *c, uint8_t session)
{
    if (session >= SMART_MAX_SESSIONS)
        return;
    c->sessions[session].open = false;
#if SMART_ENABLE_SECURE
    wipe_session_secrets(&c->sessions[session]);
#endif
}

bool smart_session_authenticated(const smart_core_t *c, uint8_t session)
{
    if (session >= SMART_MAX_SESSIONS || !c->sessions[session].open)
        return false;
#if SMART_ENABLE_SECURE
    return c->sessions[session].trusted || c->sessions[session].sec == SEC_READY;
#else
    return true;
#endif
}

void smart_session_feed(smart_core_t *c, uint8_t session, const uint8_t *data, size_t len)
{
    if (session >= SMART_MAX_SESSIONS)
        return;
    smart_session_t *ss = &c->sessions[session];
    for (size_t i = 0; i < len && ss->open; i++) {
        uint8_t b = data[i];
        if (b != 0) {
            if (ss->len < sizeof(ss->buf))
                ss->buf[ss->len++] = b;
            else
                ss->overflow = true;
            continue;
        }
        // end of packet
        if (ss->len && !ss->overflow) {
            size_t n = smart_cobs_decode(ss->buf, ss->len, ss->buf, sizeof(ss->buf));
            if (n && plain_session(c, session))
                handle_plain(c, session, ss->buf, n);
#if SMART_ENABLE_SECURE
            else if (n)
                handle_secure(c, session, ss->buf, n);
#endif
        }
        ss->len = 0;
        ss->overflow = false;
    }
}

// ---------- pairing ----------
#if SMART_ENABLE_SECURE
void smart_pairing_open(smart_core_t *c, uint32_t ms)
{
    c->pairing.state = PAIR_OPEN;
    c->pairing.until = now_ms(c) + ms;
    emit_pairing(c, SMART_PAIRING_OPENED);
}

void smart_pairing_close(smart_core_t *c)
{
    if (c->pairing.state == PAIR_CLOSED)
        return;
    c->pairing.state = PAIR_CLOSED;
    noise_wipe(c->pairing.key, 32);
    emit_pairing(c, SMART_PAIRING_CLOSED);
}

bool smart_pairing_is_open(const smart_core_t *c) { return c->pairing.state == PAIR_OPEN; }

void smart_unpair_all(smart_core_t *c)
{
    c->paired_count = 0;
    save_paired(c);
    for (uint8_t s = 0; s < SMART_MAX_SESSIONS; s++)
        if (c->sessions[s].open && !c->sessions[s].trusted)
            drop_session(c, s);
}

uint8_t smart_paired_count(const smart_core_t *c) { return c->paired_count; }

const uint8_t *smart_public_key(const smart_core_t *c) { return c->has_key ? c->public_key : NULL; }
#else
void smart_pairing_open(smart_core_t *c, uint32_t ms) { (void)c; (void)ms; }
void smart_pairing_close(smart_core_t *c) { (void)c; }
bool smart_pairing_is_open(const smart_core_t *c) { (void)c; return false; }
void smart_unpair_all(smart_core_t *c) { (void)c; }
uint8_t smart_paired_count(const smart_core_t *c) { (void)c; return 0; }
const uint8_t *smart_public_key(const smart_core_t *c) { (void)c; return NULL; }
#endif
