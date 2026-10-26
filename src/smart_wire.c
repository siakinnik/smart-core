// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 siakinnik
// CRC-16 and COBS: the byte-level framing of PROTOCOL.md.
#include "smart_core.h"

// CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final xor.
// Check value for "123456789" is 0x29B1.
uint16_t smart_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int bit = 0; bit < 8; bit++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

size_t smart_cobs_encode(const uint8_t *in, size_t len, uint8_t *out, size_t cap)
{
    if (cap == 0)
        return 0;
    size_t code_idx = 0;  // where the current block's code byte goes
    size_t w = 1;
    uint8_t code = 1;

    for (size_t r = 0; r < len; r++) {
        if (in[r] == 0) {
            out[code_idx] = code;
            code = 1;
            if (w >= cap)
                return 0;
            code_idx = w++;
        } else {
            if (w >= cap)
                return 0;
            out[w++] = in[r];
            if (++code == 0xFF) {  // block full: close it, open a new one
                out[code_idx] = code;
                code = 1;
                if (w >= cap)
                    return 0;
                code_idx = w++;
            }
        }
    }
    out[code_idx] = code;
    return w;
}

// Safe to call with out == in: the write position never passes the read position.
size_t smart_cobs_decode(const uint8_t *in, size_t len, uint8_t *out, size_t cap)
{
    size_t r = 0, w = 0;
    while (r < len) {
        uint8_t code = in[r++];
        if (code == 0)
            return 0;
        for (uint8_t i = 1; i < code; i++) {
            if (r >= len || in[r] == 0 || w >= cap)
                return 0;
            out[w++] = in[r++];
        }
        if (code != 0xFF && r < len) {
            if (w >= cap)
                return 0;
            out[w++] = 0;
        }
    }
    return w;
}
