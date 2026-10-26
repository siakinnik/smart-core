#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 siakinnik
"""Command-line tool for smart-core devices.

    smartctl.py serial:COM5 info
    smartctl.py serial:COM5 pair                 # USB: this computer may now use the network
    smartctl.py tcp:192.168.0.184 pair           # or over Wi-Fi while the pairing window is open
    smartctl.py tcp:192.168.0.184 get
    smartctl.py serial:/dev/ttyACM0 get light.brightness light.color
    smartctl.py serial:COM5 set light.effect=fire light.color=#ff3c00 light.brightness=0x80
    smartctl.py serial:COM5 set sys.wifi_ssid=Home sys.wifi_pass=secret
    smartctl.py serial:COM5 trigger sys.reboot
    smartctl.py tcp:lumenc3-62b2.local watch
    smartctl.py tcp:192.168.0.184 unpair         # forget this computer
    smartctl.py serial:COM5 unpair --all         # USB: forget every host

    smartctl.py ble scan                          # devices in pairing mode, over Bluetooth
    smartctl.py ble:LumenC3-62B2 setup --ssid Home   # pair + put it on Wi-Fi (asks the password)

Targets: serial:PORT (trusted, plain; needs pyserial), tcp:HOST[:PORT]
(default port 7531) or ble:NAME (needs bleak); both encrypted, paired
hosts only (need cryptography).
This computer's key and the devices it paired with are kept in the identity
file (--identity; default %APPDATA%/smart-core/identity.json on Windows,
~/.config/smart-core/identity.json elsewhere). Keep it private.

Values: bool on/off/true/false/1/0; numbers decimal or 0x hex; enum by name
or index; rgb #rrggbb, rrggbb or r,g,b; str as is. Several `set` pairs are
applied together (all-or-nothing).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import os
from pathlib import Path
import sys
import time

from smart_client import (
    F_LOCAL,
    F_PERSIST,
    F_READ,
    F_SECRET,
    F_WRITE,
    T_ACTION,
    T_BOOL,
    T_ENUM,
    T_I32,
    T_RGB,
    T_STR,
    T_U8,
    T_U16,
    HostIdentity,
    Prop,
    RejectedError,
    SmartDevice,
    SmartError,
    connect,
    fingerprint,
    scan_ble,
)

TYPE_NAMES = {T_BOOL: "bool", T_U8: "u8", T_U16: "u16", T_I32: "i32", T_ENUM: "enum", T_RGB: "rgb", T_STR: "str", T_ACTION: "action"}
FLAG_NAMES = ((F_READ, "R"), (F_WRITE, "W"), (F_PERSIST, "P"), (F_SECRET, "S"), (F_LOCAL, "L"))


def format_value(prop: Prop, value) -> str:
    if prop.type == T_BOOL:
        return "on" if value else "off"
    if prop.type == T_ENUM:
        return prop.options[value] if value < len(prop.options) else f"#{value}"
    if prop.type == T_RGB:
        return "#{:02x}{:02x}{:02x}".format(*value)
    if prop.type == T_STR:
        return repr(value)
    return str(value)


def parse_value(prop: Prop, text: str):
    t = prop.type
    if t == T_BOOL:
        low = text.lower()
        if low in ("on", "true", "1", "yes"):
            return True
        if low in ("off", "false", "0", "no"):
            return False
        raise SmartError(f"{prop.name}: expected on/off, got {text!r}")
    if t in (T_U8, T_U16, T_I32):
        try:
            value = int(text, 0)  # 160, 0xA0
        except ValueError:
            raise SmartError(f"{prop.name}: expected a number, got {text!r}") from None
        if prop.min is not None and not prop.min <= value <= prop.max:
            raise SmartError(f"{prop.name}: {value} is outside {prop.min}..{prop.max}")
        return value
    if t == T_ENUM:
        if text in prop.options:
            return prop.options.index(text)
        try:
            index = int(text, 0)
        except ValueError:
            raise SmartError(f"{prop.name}: expected one of {', '.join(prop.options)}") from None
        if not 0 <= index < len(prop.options):
            raise SmartError(f"{prop.name}: index {index} is outside 0..{len(prop.options) - 1}")
        return index
    if t == T_RGB:
        if "," in text:
            parts = [int(p, 0) for p in text.split(",")]
        else:
            h = text.removeprefix("#")
            if len(h) != 6:
                raise SmartError(f"{prop.name}: expected #rrggbb or r,g,b, got {text!r}")
            parts = [int(h[i : i + 2], 16) for i in (0, 2, 4)]
        if len(parts) != 3 or not all(0 <= p <= 255 for p in parts):
            raise SmartError(f"{prop.name}: expected three values 0..255")
        return tuple(parts)
    if t == T_STR:
        if prop.max_len is not None and len(text.encode()) > prop.max_len:
            raise SmartError(f"{prop.name}: longer than {prop.max_len} bytes")
        return text
    raise SmartError(f"{prop.name}: can't set a {TYPE_NAMES.get(t, t)} property")


def describe(prop: Prop) -> str:
    if prop.type in (T_U8, T_U16, T_I32):
        return f"{prop.min}..{prop.max}"
    if prop.type == T_ENUM:
        return " | ".join(prop.options)
    if prop.type == T_STR:
        return f"max {prop.max_len}"
    return ""


def flags_str(flags: int) -> str:
    return "".join(ch if flags & bit else "-" for bit, ch in FLAG_NAMES)


# ---------- commands ----------

def default_identity_path() -> Path:
    if os.name == "nt" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "smart-core" / "identity.json"
    return Path.home() / ".config" / "smart-core" / "identity.json"


async def cmd_info(dev: SmartDevice, args) -> None:
    i = dev.info
    me = args.me
    print(f"model      {i.model} (model_id 0x{i.model_id:04X})")
    print(f"device id  {i.device_id}")
    print(f"firmware   {i.firmware}")
    print(f"protocol   v{i.proto}, {i.prop_count} properties")
    if i.public_key:
        paired = "paired with this computer" if me.knows(i.public_key) else "not paired with this computer"
        print(f"device key {fingerprint(i.public_key)} ({paired})")
    print(f"link       {'encrypted (Noise)' if dev.secure else 'plain, trusted (USB)'}")
    print(f"this host  {fingerprint(me.public)}")
    print()
    print(f"{'id':<5}{'name':<20}{'type':<8}{'flags':<7}{'value':<22}range")
    for prop in sorted(dev.props.values(), key=lambda p: p.id):
        value = format_value(prop, dev.values[prop.name]) if prop.name in dev.values else ""
        print(f"0x{prop.id:02X} {prop.name:<20}{TYPE_NAMES.get(prop.type, '?'):<8}{flags_str(prop.flags):<7}{value:<22}{describe(prop)}")
    print("\nflags: R read, W write, P persist, S secret, L local (USB only)")


async def cmd_get(dev: SmartDevice, args) -> None:
    names = args.names or [p.name for p in sorted(dev.props.values(), key=lambda p: p.id) if p.name in dev.values]
    for name in names:
        prop = dev.prop(name)
        value = await dev.get(name)
        print(f"{name}={format_value(prop, value)}")


async def cmd_set(dev: SmartDevice, args) -> None:
    changes = {}
    for pair in args.pairs:
        name, sep, text = pair.partition("=")
        if not sep:
            raise SmartError(f"expected name=value, got {pair!r}")
        changes[name] = parse_value(dev.prop(name), text)
    await dev.set(changes)
    print("ok")


async def cmd_trigger(dev: SmartDevice, args) -> None:
    if dev.prop(args.name).type != T_ACTION:
        raise SmartError(f"{args.name} is not an action")
    await dev.trigger(args.name)
    print("ok")


async def cmd_watch(dev: SmartDevice, _args) -> None:
    def on_event(changed: dict) -> None:
        stamp = time.strftime("%H:%M:%S")
        text = " ".join(f"{name}={format_value(dev.props[name], value)}" for name, value in changed.items())
        print(f"{stamp} {text}", flush=True)

    dev.add_listener(on_event)
    print("watching, Ctrl+C to stop", flush=True)
    await dev.closed.wait()
    raise SmartError("connection closed")


async def cmd_pair(dev: SmartDevice, args) -> None:
    # over the network the pairing already happened in connect(pairing=True)
    if not dev.secure:
        await dev.pair(args.me)
    print(f"paired: {dev.info.model} {dev.info.device_id}, device key {fingerprint(dev.info.public_key or dev.peer_key)}")


async def cmd_unpair(dev: SmartDevice, args) -> None:
    if args.all:
        if dev.secure:
            raise SmartError("--all needs USB: over the network a host can only unpair itself")
        await dev.unpair()
        print("every host unpaired")
    else:
        await dev.unpair(args.me.public)
        print("this computer is unpaired")
    args.me.forget(dev.info.device_id)


WIFI_ERRORS = {
    "wrong_password": "wrong password",
    "no_network": "network not found (name wrong, or out of range?)",
    "failed": "couldn't connect",
}


async def _join(dev: SmartDevice, ssid: str, password: str, timeout: float = 30) -> str | None:
    """Give the device a network; wait until it's online. Returns the IP, or
    None with the reason printed."""
    state = dev.props["sys.wifi"].options
    errors = dev.props["sys.wifi_error"].options if "sys.wifi_error" in dev.props else ()
    done = asyncio.Event()

    def on_event(changed: dict) -> None:
        connected = dev.values.get("sys.wifi") == state.index("connected") and dev.values.get("sys.ip")
        failed = "sys.wifi_error" in changed and errors and errors[changed["sys.wifi_error"]] != "none"
        if connected or failed:
            done.set()

    remove = dev.add_listener(on_event)
    try:
        await dev.set({"sys.wifi_ssid": ssid, "sys.wifi_pass": password})
        print(f"joining {ssid} ...")
        try:
            await asyncio.wait_for(done.wait(), timeout)
        except asyncio.TimeoutError:
            print(f"  it didn't join within {timeout:.0f} s")
            return None
    finally:
        remove()
    if dev.values.get("sys.wifi") == state.index("connected"):
        return dev.values["sys.ip"]
    error = errors[dev.values["sys.wifi_error"]]
    print(f"  {WIFI_ERRORS.get(error, error)}")
    return None


async def cmd_setup(dev: SmartDevice, args) -> None:
    """Commission a device in pairing mode: it's paired by now; give it the
    network. Asks again on a wrong password; Enter or Ctrl+C cancels."""
    print(f"paired: {dev.info.model} {dev.info.device_id}, device key {fingerprint(dev.peer_key)}")
    ssid, password = args.ssid, args.password
    if password is None:
        password = getpass.getpass(f"password for {ssid}: ")
    try:
        while True:
            ip = await _join(dev, ssid, password)
            if ip:
                print(f"online: {ip}  ->  smartctl.py tcp:{ip} info")
                return
            if args.password is not None:  # not interactive: don't ask
                raise SmartError("setup failed")
            password = getpass.getpass(f"password for {ssid} again (Enter = cancel): ")
            if not password:
                break
    except (KeyboardInterrupt, asyncio.CancelledError):
        print()
    # cancelled: don't leave the device retrying a network that doesn't work
    with contextlib.suppress(Exception):
        await dev.set({"sys.wifi_ssid": "", "sys.wifi_pass": ""})
    raise SmartError("setup cancelled: the device forgot the network; run setup again while its pairing window is open")


COMMANDS = {
    "info": cmd_info, "get": cmd_get, "set": cmd_set, "trigger": cmd_trigger, "watch": cmd_watch,
    "pair": cmd_pair, "unpair": cmd_unpair, "setup": cmd_setup,
}


async def run_scan() -> None:
    devices = await scan_ble()
    if not devices:
        print("nothing found: switch the device into pairing mode first")
    for name, address, rssi in devices:
        print(f"{name:<20} {address}  {rssi} dBm   ->  smartctl.py ble:{name} setup --ssid ...")


async def run(args) -> None:
    if args.command == "scan":
        return await run_scan()
    dev = await connect(args.target, args.me, pairing=args.command in ("pair", "setup"))
    try:
        await COMMANDS[args.command](dev, args)
    finally:
        await dev.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Talk to a smart-core device.", epilog="see the module docstring for value formats")
    parser.add_argument("target", help="serial:PORT, tcp:HOST[:PORT], ble:NAME (or just `ble` for scan)")
    parser.add_argument("--identity", type=Path, default=default_identity_path(),
                        help="this computer's key and paired devices (default: %(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("info", help="device info and every property")
    p = sub.add_parser("get", help="read values (all if no names given)")
    p.add_argument("names", nargs="*")
    p = sub.add_parser("set", help="set name=value pairs together")
    p.add_argument("pairs", nargs="+", metavar="name=value")
    p = sub.add_parser("trigger", help="run an action")
    p.add_argument("name")
    sub.add_parser("watch", help="print changes as they happen")
    sub.add_parser("pair", help="pair this computer: over USB any time, over the network while the window is open")
    sub.add_parser("scan", help="BLE: list devices in pairing mode (target: ble)")
    p = sub.add_parser("setup", help="pair a device in pairing mode and put it on Wi-Fi")
    p.add_argument("--ssid", required=True)
    p.add_argument("--password", help="asked for if not given (keeps it out of the shell history)")
    p = sub.add_parser("unpair", help="unpair this computer")
    p.add_argument("--all", action="store_true", help="unpair every host (USB only)")
    args = parser.parse_args()
    args.me = HostIdentity.load_or_create(args.identity)

    try:
        asyncio.run(run(args))
    except RejectedError as err:
        hint = ""
        if err.code == 1:
            hint = ("\n  pair first: `smartctl.py serial:PORT pair` over USB, or open the device's"
                    " pairing window and run `pair` over the network")
        print(f"error: the device refused this computer: {err}{hint}", file=sys.stderr)
        return 1
    except SmartError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    except (OSError, asyncio.TimeoutError) as err:
        print(f"error: can't reach {args.target}: {err or 'timed out'}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
