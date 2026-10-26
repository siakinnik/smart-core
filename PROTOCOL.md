# smart-core protocol, version 2

One protocol for every device. It runs over any byte stream: USB serial,
TCP, UART, RS-485. The core does not know which one; the platform port
feeds it bytes and sends what it gives back, and tells it whether the
transport is **trusted** (physical: USB, a wire only the owner can reach)
or **untrusted** (a network, a shared bus).

- On a trusted transport packets are plain (this page, from Framing on).
- On an untrusted one every session starts with a Noise handshake, only
  paired hosts get in, and every packet is encrypted. See [Security](#security).

## Framing

Every frame is COBS-encoded and wrapped in zero bytes. On a trusted
transport the frame is a plain packet:

```
00 | COBS( TYPE | SEQ | PAYLOAD | CRC16 ) | 00
```

| Field     | Size | Description                                              |
|-----------|------|----------------------------------------------------------|
| `TYPE`    | 1    | Message type, see below                                  |
| `SEQ`     | 1    | Request number, echoed in the reply. `0` in events       |
| `PAYLOAD` | 0..N | Message data. N = `SMART_MAX_PAYLOAD` (default 240)      |
| `CRC16`   | 2    | CRC-16/CCITT-FALSE over `TYPE..PAYLOAD`, little-endian   |

- COBS removes every `00` from the data, so `00` always marks a packet
  boundary. A receiver collects bytes until `00`, decodes, checks the CRC.
- The leading `00` flushes whatever came before it. Log text on a serial
  port (anything without `00`) ends up in a bad packet that fails the CRC
  and is dropped silently.
- A packet longer than the receive buffer is dropped up to the next `00`.
- Bad packets get no reply: the sender can't be trusted to read one.

## Values

| Type      | Code | Encoding                                        |
|-----------|------|-------------------------------------------------|
| `bool`    | 1    | 1 byte, `0` / `1`                               |
| `u8`      | 2    | 1 byte                                          |
| `u16`     | 3    | 2 bytes, little-endian                          |
| `i32`     | 4    | 4 bytes, little-endian                          |
| `enum`    | 5    | 1 byte, option index                            |
| `rgb`     | 6    | 3 bytes: r, g, b                                |
| `str`     | 7    | 1 byte length + UTF-8 bytes, no terminator      |
| `action`  | 8    | nothing (setting it triggers the action)        |

A string inside a description (names, enum options) uses the same
`length + bytes` form.

## Properties

A device is a list of properties. Each has an `id` (0..254, its index),
a type, a name and flags:

| Flag      | Bit  | Meaning                                                  |
|-----------|------|----------------------------------------------------------|
| `READ`    | 0x01 | Can be read                                              |
| `WRITE`   | 0x02 | Can be set by a host                                     |
| `PERSIST` | 0x04 | Saved by the device and restored after a reboot          |
| `SECRET`  | 0x08 | Never sent back (passwords)                              |
| `LOCAL`   | 0x10 | Only over a trusted transport (USB), never over the net  |

`LOCAL` is how a host on USB sets things nobody on the network may touch,
such as Wi-Fi credentials or a factory reset. Physical access is the
authorisation.

## Messages

### Host → device

| Type   | Name       | Payload                                   | Reply            |
|--------|------------|-------------------------------------------|------------------|
| `0x01` | `HELLO`    | `proto` (u8)                              | `INFO`           |
| `0x02` | `DESCRIBE` | `id`                                      | `PROP`           |
| `0x03` | `GET`      | `id`, or `FF` for all                     | `VALUES`; for `FF`: `VALUES` × 0..n, then `ACK` |
| `0x04` | `SET`      | `id`, value, `id`, value, ...             | `ACK`            |
| `0x05` | `PING`     | —                                         | `PONG`           |
| `0x06` | `PAIR`     | host static key (32 bytes)                | `ACK`; trusted transport only |
| `0x07` | `UNPAIR`   | host static key (32), or nothing = every host | `ACK`        |

### Device → host

| Type   | Name     | Payload                                                       |
|--------|----------|---------------------------------------------------------------|
| `0x81` | `INFO`   | `proto`, `prop_count`, `model_id` (u16), device id (str), model (str), firmware (str), device static key (32 bytes, if the device does secure sessions) |
| `0x82` | `PROP`   | `id`, `type`, `flags`, name (str), type metadata              |
| `0x83` | `VALUES` | `id`, value, `id`, value, ...                                 |
| `0x84` | `ACK`    | —                                                             |
| `0x85` | `EVENT`  | same as `VALUES`; sent with `SEQ = 0`                         |
| `0x86` | `PONG`   | —                                                             |
| `0xEE` | `ERROR`  | `code`, `id` (`FF` when it's not about a property)            |

Type metadata in `PROP`:

| Type             | Metadata                          |
|------------------|-----------------------------------|
| `u8`/`u16`/`i32` | `min`, `max` in the type's size   |
| `enum`           | `count`, then `count` strings     |
| `str`            | max length (u8)                   |
| others           | nothing                           |

### Rules

- `SET` is all-or-nothing: every pair is validated first (property
  exists, writable, allowed on this transport, value in range). On the
  first problem the device replies `ERROR` and changes nothing.
- After a successful `SET` the device replies `ACK` and sends `EVENT` with
  the changed values to **every** session, including the sender. The same
  happens when the device changes something itself (a button, an effect).
  Hosts should accept `EVENT` at any time.
- `GET FF` returns every readable property that this transport may see,
  split over as many `VALUES` packets as needed, followed by an `ACK` with
  the same `SEQ` that marks the end. `SECRET` properties are never
  included; `LOCAL` ones only on a trusted transport.
- Unknown flags and types must be ignored by hosts, longer payloads than
  expected must be accepted: later versions add fields at the end.

### Error codes

| Code | Name           | Meaning                                         |
|------|----------------|-------------------------------------------------|
| `1`  | `UNKNOWN_TYPE` | Unknown message type                            |
| `2`  | `BAD_LENGTH`   | Payload too short or too long                   |
| `3`  | `UNKNOWN_PROP` | No property with that id                        |
| `4`  | `BAD_VALUE`    | Out of range, bad enum index, string too long   |
| `5`  | `READ_ONLY`    | Property can't be written                       |
| `6`  | `FORBIDDEN`    | `LOCAL` over an untrusted transport, or `GET` of something unreadable (secret, action) |
| `7`  | `BAD_PROTO`    | `HELLO` with a version the device can't speak   |
| `8`  | `PAIRING_FULL` | `PAIR` but the device's list of hosts is full   |

## Models and property names

Hosts know devices by their model. `DESCRIBE` is the fallback for a
model the database doesn't have yet (a new firmware, a homemade device)
and a debugging aid; small devices may leave it out and answer it with
`UNKNOWN_TYPE`.

- **`model_id`** in `INFO` is the device's number in the siakinnik-home
  model database. For each model (and firmware range) the database lists
  the properties by id, name, type and range, so a host doesn't need
  `DESCRIBE`. It also gives the icon, display names,
  translations, scene mappings (e.g. Yandex) and anything else that's UX,
  not protocol. `0` means "not in the database".
- **Property names** follow `group.name`, so a host that doesn't know the
  model still builds sensible entities. Properties of one group form one
  entity; the group's name says what kind:

| Group prefix | Entity  | Known names                                                        |
|--------------|---------|--------------------------------------------------------------------|
| `light`      | light   | `power` (bool), `brightness` (u8), `color` (rgb), `ct` (u16, kelvin), `effect` (enum) |
| `motor`      | fan     | `power` (bool), `speed` (u8), `direction` (enum)                   |
| `sys`        | config  | `wifi_ssid`, `wifi_pass`, `ip`, `reboot`, `reset`                  |

  Several entities of one kind get a suffix: `light2.power`, `motor2.speed`.
  Properties a host doesn't recognise become generic number / select /
  switch / text / button entities by their type. `sys.*` properties are
  usually `LOCAL` and shown as diagnostics or setup.

- A firmware update may only **append** properties: ids, names and types
  of existing ones never change. So an older database entry still drives a
  newer firmware correctly, and the host can `DESCRIBE` the ids it doesn't
  know (`INFO.prop_count` is larger than the database says).

## Discovery

Network devices advertise `_smart._tcp` over mDNS with TXT records
`id` (device id), `model`, `model_id` and `proto`. While the pairing window
is open they add `pair=1`, so a host can offer "new device, ready to pair".
The TCP port is in the SRV record.

## Security

### Keys

- Every device creates a static X25519 key pair on its first boot (from a
  hardware random generator) and keeps it in its storage. A factory reset
  erases it: the device becomes a new one.
- Every host has its own static key pair.
- The device keeps the static keys of its paired hosts (up to
  `SMART_MAX_PAIRED`, default 8). The host keeps the device's key and
  refuses to finish a handshake with a device whose key it doesn't know.

### Secure session

On an untrusted transport each frame body starts with a kind byte:

| Kind | Direction | Body |
|------|-----------|------|
| `A1` | host → device | Noise message 1: `e` (32 bytes, no payload) |
| `A2` | device → host | message 2: `e, ee, s, es` (96 bytes) |
| `A3` | host → device | message 3: `s, se` (64 bytes) |
| `A4` | both | transport message: `TYPE SEQ PAYLOAD` encrypted, + 16-byte tag (no CRC) |
| `A5` | device → host | plain reject reason (1 byte); the device then hangs up |

- Pattern **`Noise_XX_25519_ChaChaPoly_BLAKE2b`** ([Noise](https://noiseprotocol.org/noise.html),
  revision 34), the host is the initiator, prologue `smart-core/2`,
  handshake payloads empty. Both sides learn and prove each other's static
  key; recordings can't be decrypted later even if a static key leaks.
- After message 3 the device checks the host's key: paired → the session is
  open; otherwise the pairing window decides (below) or it rejects.
- Nothing but `A1`, then `A3`, is accepted before that; a plain packet,
  a malformed or late handshake (`SMART_HANDSHAKE_TIMEOUT_MS`, 5 s) ends the
  session. A transport message that doesn't decrypt (tampering, replay)
  ends it too.
- Kinds `A1`–`A5` never collide with message types, so a plain packet sent
  to a secure session is simply rejected.

| Reject | Meaning |
|--------|---------|
| `1` | `NOT_PAIRED`: the host's key isn't paired and no pairing window is open |
| `2` | `CONFLICT`: a second new host in one pairing window |
| `3` | `FULL`: the list of paired hosts is full |
| `4` | `HANDSHAKE`: malformed handshake, or the device has no key |
| `5` | `TIMEOUT`: the handshake took too long |

### Pairing

- **Over a trusted transport** (USB): `PAIR` with the host's key. Physical
  access is the consent. The host reads the device key from `INFO`.
- **Over the network or BLE**: a physical action on the device (a button,
  a few power cycles — the device firmware decides) opens the pairing
  window for a few minutes. The first unknown host that completes the
  handshake is paired; it's the only new host this window takes.
- **Commissioning**: the physical action is the owner's consent, so until
  the window ends the host paired in it may also use `LOCAL` properties
  over its untrusted link: that's how a device without USB access gets its
  Wi-Fi credentials (typically over BLE). The rights end with the window.
- **Conflict**: if a second unknown host completes a handshake before the
  window ends, somebody is racing the owner. Both are refused and the first
  one is unpaired again. The device shows it, and the owner's host reports
  `CONFLICT`: open the window again.
- **Unpairing**: `UNPAIR` over a trusted transport removes any host (or all
  of them with no key). Over a secure session a host can only remove itself;
  the device then hangs up. Removing a host closes its open sessions.
- The device reports pairing events to its firmware to show to the user
  and to switch commissioning transports: window opened, host paired, and
  exactly one end per window: conflict, timed out (nobody paired) or closed.

A pairing code (SPAKE2+) for devices that need protection even against a
host racing the owner inside the window may come in a later version.

### BLE transport

Devices that can't be reached over USB are commissioned over BLE while the
pairing window is open (and advertise only then). One GATT service carries
the same frames as any other byte stream; BLE is an untrusted transport,
so the session is the Noise handshake as above. The device opens the
session when the host subscribes to TX.

| UUID | | |
|------|---|---|
| `5ec7a3e0-6b1d-4b8e-9d2a-4c1e3f7a0001` | service | in the scan response; the advertised name identifies the device |
| `5ec7a3e0-6b1d-4b8e-9d2a-4c1e3f7a0002` | RX: write | host → device frame bytes, any split |
| `5ec7a3e0-6b1d-4b8e-9d2a-4c1e3f7a0003` | TX: notify | device → host frame bytes, split to MTU − 3 |

BLE-level pairing and encryption are not used: Noise already authenticates
and encrypts, the same way on every transport.
