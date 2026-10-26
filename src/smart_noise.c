// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 siakinnik
// Noise_XX_25519_ChaChaPoly_BLAKE2b. Follows the Noise specification
// (revision 34) section by section; names match it (MixHash, MixKey, ...).
#include "smart_noise.h"

#include <string.h>

#include "monocypher.h"

#define BLOCK_LEN 128  // BLAKE2b block size, for HMAC

static const char PROTOCOL_NAME[] = "Noise_XX_25519_ChaChaPoly_BLAKE2b";

void noise_wipe(void *p, size_t len) { crypto_wipe(p, len); }

bool noise_equal32(const uint8_t a[32], const uint8_t b[32]) { return crypto_verify32(a, b) == 0; }

void noise_public_key(uint8_t pub[32], const uint8_t secret[32]) { crypto_x25519_public_key(pub, secret); }

// ---------- 4.1 DH ----------
// A shared secret of all zeros means the other side sent a low-order point.
static bool dh(uint8_t out[32], const uint8_t secret[32], const uint8_t pub[32])
{
    static const uint8_t zero[32] = { 0 };
    crypto_x25519(out, secret, pub);
    return crypto_verify32(out, zero) != 0;
}

// ---------- 4.2 cipher: ChaCha20-Poly1305 (RFC 8439), nonce = 32 zero bits + n little-endian ----------
static void make_nonce(uint8_t nonce[12], uint64_t n)
{
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(n >> (8 * i));
}

// A fresh Monocypher context per message: its first message is plain RFC 8439
// (later messages on the same context would be re-keyed, which Noise doesn't do).
static void aead_encrypt(const uint8_t k[32], uint64_t n, const uint8_t *ad, size_t ad_len,
                         const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t nonce[12];
    crypto_aead_ctx ctx;
    make_nonce(nonce, n);
    crypto_aead_init_ietf(&ctx, k, nonce);
    crypto_aead_write(&ctx, out, out + len, ad, ad_len, in, len);
    crypto_wipe(&ctx, sizeof(ctx));
}

static bool aead_decrypt(const uint8_t k[32], uint64_t n, const uint8_t *ad, size_t ad_len,
                         const uint8_t *in, size_t len, uint8_t *out)
{
    if (len < NOISE_TAG_LEN)
        return false;
    uint8_t nonce[12], tag[NOISE_TAG_LEN];
    crypto_aead_ctx ctx;
    size_t text = len - NOISE_TAG_LEN;
    memcpy(tag, in + text, NOISE_TAG_LEN);  // `out` may overlap `in`
    make_nonce(nonce, n);
    crypto_aead_init_ietf(&ctx, k, nonce);
    int bad = crypto_aead_read(&ctx, out, tag, ad, ad_len, in, text);
    crypto_wipe(&ctx, sizeof(ctx));
    return bad == 0;
}

void noise_encrypt(noise_cipher_t *c, const uint8_t *in, size_t len, uint8_t *out)
{
    aead_encrypt(c->k, c->n++, NULL, 0, in, len, out);
}

bool noise_decrypt(noise_cipher_t *c, const uint8_t *in, size_t len, uint8_t *out)
{
    if (!aead_decrypt(c->k, c->n, NULL, 0, in, len, out))
        return false;
    c->n++;
    return true;
}

// ---------- 4.3 hash: BLAKE2b-512, HMAC and HKDF ----------
static void hmac(uint8_t out[NOISE_HASH_LEN], const uint8_t *key, size_t key_len,
                 const uint8_t *d1, size_t l1, const uint8_t *d2, size_t l2)
{
    uint8_t pad[BLOCK_LEN], inner[NOISE_HASH_LEN];
    crypto_blake2b_ctx ctx;

    memset(pad, 0, sizeof(pad));
    memcpy(pad, key, key_len);  // keys here are at most NOISE_HASH_LEN bytes
    for (int i = 0; i < BLOCK_LEN; i++)
        pad[i] ^= 0x36;
    crypto_blake2b_init(&ctx, NOISE_HASH_LEN);
    crypto_blake2b_update(&ctx, pad, BLOCK_LEN);
    crypto_blake2b_update(&ctx, d1, l1);
    crypto_blake2b_update(&ctx, d2, l2);
    crypto_blake2b_final(&ctx, inner);

    for (int i = 0; i < BLOCK_LEN; i++)
        pad[i] ^= 0x36 ^ 0x5c;
    crypto_blake2b_init(&ctx, NOISE_HASH_LEN);
    crypto_blake2b_update(&ctx, pad, BLOCK_LEN);
    crypto_blake2b_update(&ctx, inner, NOISE_HASH_LEN);
    crypto_blake2b_final(&ctx, out);

    crypto_wipe(pad, sizeof(pad));
    crypto_wipe(inner, sizeof(inner));
}

// HKDF with two outputs (all Noise needs here)
static void hkdf2(const uint8_t ck[NOISE_HASH_LEN], const uint8_t *ikm, size_t ikm_len,
                  uint8_t out1[NOISE_HASH_LEN], uint8_t out2[NOISE_HASH_LEN])
{
    static const uint8_t one = 1, two = 2;
    uint8_t temp[NOISE_HASH_LEN];
    hmac(temp, ck, NOISE_HASH_LEN, ikm, ikm_len, NULL, 0);
    hmac(out1, temp, NOISE_HASH_LEN, &one, 1, NULL, 0);
    hmac(out2, temp, NOISE_HASH_LEN, out1, NOISE_HASH_LEN, &two, 1);
    crypto_wipe(temp, sizeof(temp));
}

// ---------- 5.2 SymmetricState ----------
static void mix_hash(noise_hs_t *hs, const uint8_t *data, size_t len)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, NOISE_HASH_LEN);
    crypto_blake2b_update(&ctx, hs->h, NOISE_HASH_LEN);
    crypto_blake2b_update(&ctx, data, len);
    crypto_blake2b_final(&ctx, hs->h);
}

static void mix_key(noise_hs_t *hs, const uint8_t *ikm, size_t len)
{
    uint8_t temp_k[NOISE_HASH_LEN];
    hkdf2(hs->ck, ikm, len, hs->ck, temp_k);
    memcpy(hs->cs.k, temp_k, NOISE_KEY_LEN);  // truncated to 32 bytes
    hs->cs.n = 0;
    hs->cs.has_key = true;
    crypto_wipe(temp_k, sizeof(temp_k));
}

// DH, then MixKey on the result
static bool mix_dh(noise_hs_t *hs, const uint8_t secret[32], const uint8_t pub[32])
{
    uint8_t shared[32];
    bool ok = dh(shared, secret, pub);
    mix_key(hs, shared, sizeof(shared));
    crypto_wipe(shared, sizeof(shared));
    return ok;
}

static size_t encrypt_and_hash(noise_hs_t *hs, const uint8_t *in, size_t len, uint8_t *out)
{
    size_t out_len = len;
    if (hs->cs.has_key) {
        aead_encrypt(hs->cs.k, hs->cs.n++, hs->h, NOISE_HASH_LEN, in, len, out);
        out_len += NOISE_TAG_LEN;
    } else if (len) {
        memmove(out, in, len);
    }
    mix_hash(hs, out, out_len);
    return out_len;
}

// `len` is the ciphertext length (with the tag when there's a key)
static bool decrypt_and_hash(noise_hs_t *hs, const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t h[NOISE_HASH_LEN];
    memcpy(h, hs->h, NOISE_HASH_LEN);
    mix_hash(hs, in, len);  // hash the ciphertext before `out` may overwrite it
    if (!hs->cs.has_key) {
        if (len)
            memmove(out, in, len);
        return true;
    }
    if (!aead_decrypt(hs->cs.k, hs->cs.n, h, NOISE_HASH_LEN, in, len, out))
        return false;
    hs->cs.n++;
    return true;
}

static void split(noise_hs_t *hs, noise_cipher_t *c1, noise_cipher_t *c2)
{
    uint8_t k1[NOISE_HASH_LEN], k2[NOISE_HASH_LEN];
    hkdf2(hs->ck, NULL, 0, k1, k2);
    memcpy(c1->k, k1, NOISE_KEY_LEN);
    memcpy(c2->k, k2, NOISE_KEY_LEN);
    c1->n = c2->n = 0;
    c1->has_key = c2->has_key = true;
    crypto_wipe(k1, sizeof(k1));
    crypto_wipe(k2, sizeof(k2));
    // the handshake state is spent: forget every secret in it
    crypto_wipe(hs->e, sizeof(hs->e));
    crypto_wipe(&hs->cs, sizeof(hs->cs));
    crypto_wipe(hs->ck, sizeof(hs->ck));
}

// ---------- 5.3 HandshakeState ----------
void noise_hs_init(noise_hs_t *hs, const uint8_t *prologue, size_t prologue_len,
                   const uint8_t s[32], const uint8_t s_pub[32], const uint8_t e[32])
{
    memset(hs, 0, sizeof(*hs));
    // the name is shorter than HASHLEN: h = name padded with zeros
    memcpy(hs->h, PROTOCOL_NAME, sizeof(PROTOCOL_NAME) - 1);
    memcpy(hs->ck, hs->h, NOISE_HASH_LEN);
    mix_hash(hs, prologue, prologue_len);
    hs->s = s;
    hs->s_pub = s_pub;
    memcpy(hs->e, e, 32);
    crypto_x25519_public_key(hs->e_pub, hs->e);
}

// -> e
void noise_xx_write1(noise_hs_t *hs, const uint8_t *payload, size_t len, uint8_t *out)
{
    memcpy(out, hs->e_pub, 32);
    mix_hash(hs, hs->e_pub, 32);
    encrypt_and_hash(hs, payload, len, out + 32);
}

void noise_xx_read1(noise_hs_t *hs, const uint8_t *in, size_t in_len, uint8_t *payload)
{
    memcpy(hs->re, in, 32);
    mix_hash(hs, hs->re, 32);
    decrypt_and_hash(hs, in + 32, in_len - 32, payload);
}

// <- e, ee, s, es
bool noise_xx_write2(noise_hs_t *hs, const uint8_t *payload, size_t len, uint8_t *out)
{
    memcpy(out, hs->e_pub, 32);
    mix_hash(hs, hs->e_pub, 32);
    bool ok = mix_dh(hs, hs->e, hs->re);                  // ee
    encrypt_and_hash(hs, hs->s_pub, 32, out + 32);       // s
    ok &= mix_dh(hs, hs->s, hs->re);                      // es (responder: DH(s, re))
    encrypt_and_hash(hs, payload, len, out + 32 + 48);
    return ok;
}

bool noise_xx_read2(noise_hs_t *hs, const uint8_t *in, size_t in_len, uint8_t *payload)
{
    if (in_len < NOISE_XX_MSG2_LEN(0))
        return false;
    memcpy(hs->re, in, 32);
    mix_hash(hs, hs->re, 32);
    if (!mix_dh(hs, hs->e, hs->re))                       // ee
        return false;
    if (!decrypt_and_hash(hs, in + 32, 48, hs->rs))       // s
        return false;
    if (!mix_dh(hs, hs->e, hs->rs))                       // es (initiator: DH(e, rs))
        return false;
    return decrypt_and_hash(hs, in + 80, in_len - 80, payload);
}

// -> s, se
bool noise_xx_write3(noise_hs_t *hs, const uint8_t *payload, size_t len, uint8_t *out,
                     noise_cipher_t *send, noise_cipher_t *recv)
{
    encrypt_and_hash(hs, hs->s_pub, 32, out);             // s
    bool ok = mix_dh(hs, hs->s, hs->re);                  // se (initiator: DH(s, re))
    encrypt_and_hash(hs, payload, len, out + 48);
    split(hs, send, recv);  // initiator sends with the first key
    return ok;
}

bool noise_xx_read3(noise_hs_t *hs, const uint8_t *in, size_t in_len, uint8_t *payload,
                    noise_cipher_t *send, noise_cipher_t *recv)
{
    if (in_len < NOISE_XX_MSG3_LEN(0))
        return false;
    if (!decrypt_and_hash(hs, in, 48, hs->rs))            // s
        return false;
    if (!mix_dh(hs, hs->e, hs->rs))                       // se (responder: DH(e, rs))
        return false;
    if (!decrypt_and_hash(hs, in + 48, in_len - 48, payload))
        return false;
    split(hs, recv, send);  // responder receives with the first key
    return true;
}
