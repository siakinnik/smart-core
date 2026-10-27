// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 siakinnik
// Compile-time limits. Override any of them with -D in the device build
// (or Kconfig on ESP-IDF). Small MCUs (AVR) want much smaller values.
#pragma once

#if defined(ESP_PLATFORM) && __has_include("sdkconfig.h")
#include "sdkconfig.h"
#ifdef CONFIG_SMART_MAX_PROPS
#define SMART_MAX_PROPS CONFIG_SMART_MAX_PROPS
#endif
#ifdef CONFIG_SMART_MAX_SESSIONS
#define SMART_MAX_SESSIONS CONFIG_SMART_MAX_SESSIONS
#endif
#ifdef CONFIG_SMART_MAX_PAYLOAD
#define SMART_MAX_PAYLOAD CONFIG_SMART_MAX_PAYLOAD
#endif
#ifdef CONFIG_SMART_ENABLE_DESCRIBE
#define SMART_ENABLE_DESCRIBE 1
#else
#define SMART_ENABLE_DESCRIBE 0
#endif
#ifdef CONFIG_SMART_ENABLE_SECURE
#define SMART_ENABLE_SECURE 1
#else
#define SMART_ENABLE_SECURE 0
#endif
#ifdef CONFIG_SMART_MAX_PAIRED
#define SMART_MAX_PAIRED CONFIG_SMART_MAX_PAIRED
#endif
#ifdef CONFIG_SMART_ENABLE_OTA
#define SMART_ENABLE_OTA 1
#else
#define SMART_ENABLE_OTA 0
#endif
#endif

#ifndef SMART_MAX_PROPS
#define SMART_MAX_PROPS 24        // properties per device (ids 0..SMART_MAX_PROPS-1)
#endif

#ifndef SMART_MAX_SESSIONS
#define SMART_MAX_SESSIONS 4      // simultaneous hosts (USB + TCP connections)
#endif

#ifndef SMART_MAX_PAYLOAD
#define SMART_MAX_PAYLOAD 240     // longest payload of one packet
#endif

// DESCRIBE support. Hosts normally know a device from its model_id (the
// siakinnik-home model database); DESCRIBE is the fallback for models the
// database doesn't know yet, and for debugging. Set to 0 on tiny MCUs: the
// device then answers DESCRIBE with UNKNOWN_TYPE.
#ifndef SMART_ENABLE_DESCRIBE
#define SMART_ENABLE_DESCRIBE 1
#endif

#ifndef SMART_PERSIST_DELAY_MS
#define SMART_PERSIST_DELAY_MS 3000  // save PERSIST props this long after the last change
#endif

// Secure sessions (Noise) and pairing for untrusted transports. Without it,
// untrusted sessions speak plain packets: only for devices that never sit
// on a network (e.g. a tiny MCU on a private wire).
#ifndef SMART_ENABLE_SECURE
#define SMART_ENABLE_SECURE 1
#endif

#ifndef SMART_MAX_PAIRED
#define SMART_MAX_PAIRED 8              // hosts that may open secure sessions
#endif

// Signed firmware updates over the protocol (OTA_BEGIN / OTA_DATA / OTA_END).
#ifndef SMART_ENABLE_OTA
#define SMART_ENABLE_OTA SMART_ENABLE_SECURE
#endif

#ifndef SMART_HANDSHAKE_TIMEOUT_MS
#define SMART_HANDSHAKE_TIMEOUT_MS 5000  // an untrusted session must finish the handshake by then
#endif

// The largest frame body: TYPE + SEQ + PAYLOAD + CRC16 on a trusted session,
// KIND + TYPE + SEQ + PAYLOAD + tag on a secure one, or a handshake message
// (the biggest is 1 + 96 bytes). And the COBS-encoded size of that.
#define SMART_RAW_DATA (SMART_MAX_PAYLOAD + 19)
#define SMART_MAX_RAW (SMART_RAW_DATA > 97 ? SMART_RAW_DATA : 97)
#define SMART_MAX_PACKET (SMART_MAX_RAW + SMART_MAX_RAW / 254 + 1)

#if SMART_MAX_PROPS > 254
#error "SMART_MAX_PROPS must be at most 254 (0xFF means 'all')"
#endif
#if SMART_MAX_PAYLOAD < 32
#error "SMART_MAX_PAYLOAD must be at least 32"
#endif
#if SMART_MAX_PAIRED < 1 || SMART_MAX_PAIRED > 32
#error "SMART_MAX_PAIRED must be 1..32"
#endif
