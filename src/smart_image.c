// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 siakinnik
// Signed firmware images: SHA-512 and the manifest (see smart_core.h).
// Ed25519 is the standard one (RFC 8032), so images can be signed with any
// ordinary Ed25519 tool.
#include <string.h>

#include "monocypher-ed25519.h"
#include "smart_core.h"

// smart_hash_t is opaque storage for Monocypher's context (C99: no _Static_assert)
typedef char smart_hash_fits[sizeof(smart_hash_t) >= sizeof(crypto_sha512_ctx) ? 1 : -1];

static const char MAGIC[8] = { 'S', 'M', 'A', 'R', 'T', 'F', 'W', '1' };

void smart_hash_init(smart_hash_t *h) { crypto_sha512_init((crypto_sha512_ctx *)h); }

void smart_hash_update(smart_hash_t *h, const uint8_t *data, size_t len)
{
    crypto_sha512_update((crypto_sha512_ctx *)h, data, len);
}

void smart_hash_final(smart_hash_t *h, uint8_t out[64]) { crypto_sha512_final((crypto_sha512_ctx *)h, out); }

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

bool smart_manifest_parse(const uint8_t raw[SMART_MANIFEST_LEN], smart_manifest_t *out)
{
    if (memcmp(raw, MAGIC, sizeof(MAGIC)) != 0)
        return false;
    // the signature covers everything before it, with the signer key inside
    if (crypto_ed25519_check(raw + 148, raw + 116, raw, 148) != 0)
        return false;
    out->model_id = (uint16_t)(raw[8] | raw[9] << 8);
    out->security_version = le32(raw + 12);
    out->image_size = le32(raw + 16);
    memcpy(out->version, raw + 20, 32);
    out->version[32] = 0;
    memcpy(out->hash, raw + 52, 64);
    memcpy(out->signer, raw + 116, 32);
    return true;
}
