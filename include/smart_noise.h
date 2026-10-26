// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 siakinnik
// Noise_XX_25519_ChaChaPoly_BLAKE2b (noiseprotocol.org, revision 34) on top
// of Monocypher: only what smart-core needs. Internal header; the tests use
// it too, to play the host side.
//
//   XX:  -> e
//        <- e, ee, s, es
//        -> s, se
//
// Both sides end up knowing each other's static key; nobody learns anything
// from a recording of the session even if a static key leaks later.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NOISE_KEY_LEN 32
#define NOISE_HASH_LEN 64
#define NOISE_TAG_LEN 16

// handshake message sizes with a payload of `p` bytes
#define NOISE_XX_MSG1_LEN(p) (32 + (p))
#define NOISE_XX_MSG2_LEN(p) (32 + 48 + (p) + 16)
#define NOISE_XX_MSG3_LEN(p) (48 + (p) + 16)

typedef struct {
    uint8_t k[NOISE_KEY_LEN];
    uint64_t n;
    bool has_key;
} noise_cipher_t;

typedef struct {
    noise_cipher_t cs;
    uint8_t ck[NOISE_HASH_LEN];
    uint8_t h[NOISE_HASH_LEN];
    const uint8_t *s, *s_pub;  // our static key pair (owned by the caller)
    uint8_t e[32], e_pub[32];  // our ephemeral key pair
    uint8_t re[32], rs[32];    // the other side's ephemeral and static keys
} noise_hs_t;

// Start a handshake. `e` is a fresh random ephemeral secret.
void noise_hs_init(noise_hs_t *hs, const uint8_t *prologue, size_t prologue_len,
                   const uint8_t s[32], const uint8_t s_pub[32], const uint8_t e[32]);

// Initiator (host). Each returns false if the message doesn't authenticate.
void noise_xx_write1(noise_hs_t *hs, const uint8_t *payload, size_t len, uint8_t *out);
bool noise_xx_read2(noise_hs_t *hs, const uint8_t *in, size_t in_len, uint8_t *payload);
bool noise_xx_write3(noise_hs_t *hs, const uint8_t *payload, size_t len, uint8_t *out,
                     noise_cipher_t *send, noise_cipher_t *recv);

// Responder (device).
void noise_xx_read1(noise_hs_t *hs, const uint8_t *in, size_t in_len, uint8_t *payload);
bool noise_xx_write2(noise_hs_t *hs, const uint8_t *payload, size_t len, uint8_t *out);
bool noise_xx_read3(noise_hs_t *hs, const uint8_t *in, size_t in_len, uint8_t *payload,
                    noise_cipher_t *send, noise_cipher_t *recv);

// Transport messages: `out` gets len + NOISE_TAG_LEN bytes. In-place is fine.
void noise_encrypt(noise_cipher_t *c, const uint8_t *in, size_t len, uint8_t *out);
// `len` includes the tag; `out` gets len - NOISE_TAG_LEN bytes.
bool noise_decrypt(noise_cipher_t *c, const uint8_t *in, size_t len, uint8_t *out);

// X25519 public key for a secret.
void noise_public_key(uint8_t pub[32], const uint8_t secret[32]);

// Erase secrets.
void noise_wipe(void *p, size_t len);

// Constant-time comparison of two 32-byte keys.
bool noise_equal32(const uint8_t a[32], const uint8_t b[32]);
