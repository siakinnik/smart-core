# smart-core

One device protocol for every siakinnik-home device: a light strip, a lamp,
a projector with a motor, a sensor on a wire. Portable C99, no `malloc`, no
OS, no platform code. The same core runs on an ESP32, an STM32 or an AVR;
the device only tells it how to send bytes and where to store them.

- **Any byte stream.** USB serial, TCP, BLE, UART, RS-485: COBS-framed
  packets, the core doesn't care which.
- **Properties, not commands.** A device is a list of typed properties
  (`light.power`, `light.brightness`, `sys.wifi_ssid`, ...). Hosts get,
  set and watch them; every change is pushed to every host.
- **Secure by default.** A physical link (USB) is trusted. Anything else
  runs a Noise handshake (`Noise_XX_25519_ChaChaPoly_BLAKE2b`) first, and
  only paired hosts get in. Every packet is encrypted and authenticated.
- **Pairing like Matter / HomeKit.** Over USB, or in a pairing window
  opened by a physical action on the device; the host paired in the window
  may commission the device (give it Wi-Fi) over BLE.
- **Signed firmware updates.** Over any link; the device installs only
  images signed with the key its firmware was built with (Ed25519).
- **Small.** About 5 KB of RAM with 4 sessions and crypto, 760 bytes in
  the smallest configuration; about 38 KB of flash with crypto on an ESP32-C3.

The wire format is in [PROTOCOL.md](PROTOCOL.md).

## Layout

```
include/            smart_core.h (API), smart_config.h (limits), smart_noise.h
src/                smart_core.c  properties, sessions, messages, pairing, OTA
                    smart_wire.c  CRC-16 + COBS
                    smart_noise.c Noise XX (only with SMART_ENABLE_SECURE)
                    smart_image.c signed images: SHA-512, manifest, Ed25519
third_party/        Monocypher 4.0.3: X25519, ChaCha20-Poly1305, BLAKE2b, Ed25519
clients/python/     smart_client.py (host library), smartctl.py (CLI),
                    smartsign.py (signing keys and signed images)
tests/              C unit tests, an emulator, Python end-to-end tests
```

## Building it into a device

**ESP-IDF.** Add the repository as `components/smart-core` (a git
submodule). It registers itself as a component; the limits show up in
`idf.py menuconfig` under *smart-core*.

```bash
git submodule add https://github.com/siakinnik/smart-core components/smart-core
```

**CMake** (Linux, Windows, macOS, STM32 or Zephyr with CMake):

```cmake
add_subdirectory(smart-core)
target_link_libraries(my_app PRIVATE smart_core)
```

**Anything else** (an Arduino or PlatformIO library, STM32CubeIDE, a
Makefile): compile these files as C99 and add `include/` and
`third_party/monocypher/` to the include path.

```
src/smart_core.c  src/smart_wire.c  src/smart_noise.c  src/smart_image.c
third_party/monocypher/monocypher.c  third_party/monocypher/monocypher-ed25519.c
```

**A tiny MCU that never sits on a network** (an AVR on a private wire):
`-DSMART_ENABLE_SECURE=0`. Only `smart_core.c` and `smart_wire.c` are
needed then; no crypto is compiled.

### Configuration

Set with `-D...` (or Kconfig on ESP-IDF).

| Macro | Default | Meaning |
|---|---|---|
| `SMART_MAX_PROPS` | 24 | Properties per device |
| `SMART_MAX_SESSIONS` | 4 | Hosts at once (USB + network) |
| `SMART_MAX_PAYLOAD` | 240 | Longest packet payload |
| `SMART_ENABLE_SECURE` | 1 | Noise sessions and pairing on untrusted links |
| `SMART_ENABLE_OTA` | = SECURE | Signed firmware updates (`ota_begin/write/finish` in the port) |
| `SMART_MAX_PAIRED` | 8 | Hosts that may be paired |
| `SMART_ENABLE_DESCRIBE` | 1 | Self-description for models a host doesn't know |
| `SMART_PERSIST_DELAY_MS` | 3000 | Save persistent properties this long after the last change |
| `SMART_HANDSHAKE_TIMEOUT_MS` | 5000 | Time an untrusted session gets to finish the handshake |

| Configuration | RAM for the core |
|---|---|
| Defaults (4 sessions, secure) | ≈ 5.2 KB, ≈ 720 B per session |
| 2 sessions, secure | ≈ 3.8 KB |
| 1 session, no crypto, 8 properties, payload 48 | ≈ 760 B |

Measured on a 64-bit host; 32-bit MCUs need a little less. The handshake
runs X25519 and needs a few KB of stack in the task that feeds untrusted
sessions.

## Porting to a device

The device gives the core six callbacks and calls it from one task (or
under one recursive mutex: `on_change` runs inside `smart_session_feed`).

```c
#include "smart_core.h"

static const smart_port_t port = {
    .millis      = my_millis,     // monotonic milliseconds
    .send        = my_send,       // bytes for session N to its transport
    .store_read  = my_nvs_read,   // persistent storage by short key
    .store_write = my_nvs_write,
    .random      = my_trng,       // hardware RNG, needed for the device key
    .close       = my_hang_up,    // the core gave up on an untrusted session
};

static smart_core_t core;
static uint8_t P_POWER, P_BRIGHT, P_SSID;
static uint8_t usb, net;  // session ids
static char ssid[33];

void device_start(void)
{
    smart_config_t cfg = {
        .port = &port, .device_id = "AA:BB:CC:DD:EE:FF",
        .model_id = 0x0002, .model = "mylamp", .firmware = "1.0.0",
        .on_change = on_change,    // a host changed something
        .on_pairing = on_pairing,  // pairing window events, to show the user
    };
    smart_init(&core, &cfg);

    // Ids are part of the model: only ever append, never reorder.
    P_POWER  = smart_prop_bool(&core, "light.power", SMART_F_RW | SMART_F_PERSIST, true);
    P_BRIGHT = smart_prop_u8(&core, "light.brightness", SMART_F_RW | SMART_F_PERSIST, 1, 255, 128);
    P_SSID   = smart_prop_str(&core, "sys.wifi_ssid", SMART_F_RW | SMART_F_LOCAL | SMART_F_PERSIST, ssid, 32);

    smart_load(&core);  // values, the device key (made on first boot), paired hosts

    usb = smart_session_open(&core, true);  // a physical link: trusted
}

// transports
void on_tcp_connect(void)                              { net = smart_session_open(&core, false); }
void on_bytes(uint8_t s, const uint8_t *d, size_t n)   { smart_session_feed(&core, s, d, n); }
void on_disconnect(uint8_t s)                          { smart_session_close(&core, s); }

// every few milliseconds: persistence, handshake timeouts, the pairing window
void tick(void) { smart_poll(&core); }

// a button, a few power cycles: the owner lets one new host pair
void on_pair_button(void) { smart_pairing_open(&core, 180000); }

// the device changes something itself: every host gets an EVENT
void on_knob(uint8_t level) { smart_set_u8(&core, P_BRIGHT, level); }
```

What the core enforces:

- A **trusted** session (USB, a wire only the owner can reach) speaks
  plain packets, may use `LOCAL` properties and may pair hosts.
- An **untrusted** session (TCP, BLE, a shared bus) processes nothing
  until a paired host completes the Noise handshake. A plain packet, a bad
  handshake or a tampered frame ends it.
- The **pairing window** takes exactly one new host. A second one in the
  same window is a conflict: both are refused. Until the window ends the
  host paired in it may set `LOCAL` properties (commissioning).

A complete port with USB, TCP and BLE transports is
[LumenC3](https://github.com/siakinnik/LumenC3) (`main/smart_esp.c`,
`main/smart_ble.c`).

## Firmware updates

The device gets the update key and its security version in
`smart_config_t` (`ota_key`, `security_version`) and three port callbacks
to write the image (`ota_begin`, `ota_write`, `ota_finish`). The core checks
the signature, the model, the version and the hash; the port only writes
and picks the boot slot.

```bash
python smartsign.py keygen ~/.config/smart-core/mydevice.key   # once; .pub goes into the firmware build
python smartsign.py sign build/mydevice.bin --key ~/.config/smart-core/mydevice.key --model-id 0x0002
python smartctl.py tcp:192.168.0.50 update build/mydevice.simg
```

The private key stays with whoever releases the firmware: never commit it.
A signed image can also be flashed over USB like a plain one.

## Host side

`clients/python/smart_client.py` is the host library (asyncio; the
siakinnik-home Home Assistant integration builds on it). `smartctl.py` is a
command-line tool on top of it.

```bash
pip install cryptography pyserial bleak   # bleak only for BLE

python smartctl.py serial:COM5 info                     # every property
python smartctl.py serial:COM5 pair                     # pair this computer over USB
python smartctl.py tcp:192.168.0.184 set light.brightness=0x80
python smartctl.py tcp:lumenc3-62b2.local watch         # changes as they happen
python smartctl.py ble scan                             # devices in pairing mode
python smartctl.py ble:LumenC3-62B2 setup --ssid Home   # pair + give it Wi-Fi
```

`smartctl` keeps this computer's key and the devices it paired with in
`%APPDATA%\smart-core\identity.json` (`~/.config/smart-core/identity.json`
elsewhere).

## Tests

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build
```

- `core`: every message type, validation, persistence, sessions, pairing
  and conflicts, tampering and replay, RFC 8439 and RFC 7748 vectors.
- `client`: the Python client against the C emulator over TCP and a
  pseudo-terminal: the C and Python halves of the handshake must agree.
- `noise_interop`: the Python Noise against the independent
  `noiseprotocol` package (skipped unless `pip install noiseprotocol`).

For sanitizers, add `-DCMAKE_C_FLAGS="-fsanitize=address,undefined"`.

## License

GPL-3.0-or-later, see [LICENSE](LICENSE). Firmware that includes the core
is GPL too. Monocypher is used under CC0-1.0; see [NOTICE](NOTICE).

## Contributing

Pull requests are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md). Before
the first one is merged, its author signs the [CLA](CLA.md) with one comment
in the pull request.
