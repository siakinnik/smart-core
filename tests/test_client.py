# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 siakinnik
"""End-to-end: the Python client against the C emulator over real TCP.

    python3 test_client.py path/to/smart_emulator

Connections from 127.0.0.2 are the emulator's trusted "USB" (plain packets);
everything else must do the Noise handshake as a paired host. So this also
checks that the Python and C halves of the handshake agree.
"""

import asyncio
import contextlib
import subprocess
import sys

from smart_client import (
    F_LOCAL,
    T_ENUM,
    HostIdentity,
    RejectedError,
    SmartDevice,
    SmartError,
    build_packet,
    cobs_decode,
    cobs_encode,
    connect,
    crc16,
)


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_framing():
    check(crc16(b"123456789") == 0x29B1, "crc16 check value")
    for data in (b"", b"\x00", b"\x01\x00\x02", bytes(range(256)) * 3, b"\xff" * 600):
        enc = cobs_encode(data)
        check(0 not in enc, "cobs output has zeros")
        check(cobs_decode(enc) == data, f"cobs round trip {len(data)}")
    check(build_packet(0x05, 1)[0] == 0 and build_packet(0x05, 1)[-1] == 0, "packet delimiters")


class Emulator:
    def __init__(self, path: str, pairing_seconds: int = 0, env: dict | None = None) -> None:
        self.path = path
        self.pairing = pairing_seconds
        self.env = env
        self.lines: list[str] = []

    async def __aenter__(self):
        args = [self.path, "0"] + ([str(self.pairing)] if self.pairing else [])
        self.proc = await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, env=self.env)
        self.port = int((await self.proc.stdout.readline()).decode().split()[1])
        self._reader = asyncio.create_task(self._read())
        return self

    async def _read(self):
        while line := await self.proc.stdout.readline():
            self.lines.append(line.decode().strip())

    async def __aexit__(self, *exc):
        self.proc.terminate()
        await self.proc.wait()
        self._reader.cancel()

    async def usb(self) -> SmartDevice:
        """The trusted session: plain packets from 127.0.0.2."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port, local_addr=("127.0.0.2", 0))
        return await SmartDevice.connect_plain(reader, writer)

    async def net(self, me: HostIdentity, **kw) -> SmartDevice:
        return await SmartDevice.connect_tcp("127.0.0.1", self.port, me, **kw)


async def expect_error(coro, cls=SmartError, code=None, what=""):
    try:
        dev = await coro
    except cls as err:
        if code is not None:
            check(getattr(err, "code", None) == code, f"{what}: code {getattr(err, 'code', None)} != {code} ({err})")
        return err
    await dev.close()
    raise AssertionError(f"{what}: no error")


async def run(emulator: str) -> None:
    async with Emulator(emulator) as emu:
        me = HostIdentity.create()
        usb = await emu.usb()
        check(usb.info.public_key is not None and len(usb.info.public_key) == 32, "INFO carries the device key")

        # nobody is paired yet: the network is closed to everyone
        await expect_error(emu.net(me, pairing=True), RejectedError, 1, "unpaired host")
        # and without pairing=True the client won't even finish a handshake with an unknown device
        err = await expect_error(emu.net(me), SmartError, None, "unknown device key")
        check("unknown device key" in str(err), f"client refuses unknown device: {err}")

        await usb.pair(me)
        check(me.devices == {usb.info.device_id: usb.info.public_key}, "device remembered")
        net = await emu.net(me)
        try:
            check(net.secure and net.peer_key == usb.info.public_key, "secure session to the paired device")
            check(net.info.model == "lumenc3" and net.info.model_id == 1, "info")
            check(len(net.props) == net.info.prop_count == 10, "describe")
            effect = net.props["light.effect"]
            check(effect.type == T_ENUM and effect.options[2] == "fire", "enum options")
            check(net.props["sys.wifi_ssid"].flags & F_LOCAL, "local flag")

            check(net.values["light.brightness"] == 160, "initial value")
            check("sys.wifi_ssid" not in net.values, "local prop hidden from the network")
            check("sys.wifi_ssid" in usb.values, "local prop visible on usb")
            check("sys.wifi_pass" not in usb.values, "secret never sent")

            events = []
            usb.add_listener(events.append)
            await net.set({"light.brightness": 80, "light.color": (255, 0, 0), "light.effect": "fire"})
            await asyncio.sleep(0.1)
            check(net.values["light.brightness"] == 80, "own state updated by EVENT")
            check(usb.values["light.effect"] == 2 and usb.values["light.color"] == (255, 0, 0), "other host got EVENT")
            check(events and events[-1].keys() == {"light.brightness", "light.color", "light.effect"}, "event contents")

            try:
                await net.set({"light.brightness": 0})
                check(False, "out of range accepted")
            except SmartError as err:
                check(err.code == 4 and err.prop == "light.brightness", f"range error: {err}")
            check(net.values["light.brightness"] == 80, "failed set changed nothing")

            try:
                await net.set({"sys.wifi_ssid": "home"})
                check(False, "local over network accepted")
            except SmartError as err:
                check(err.code == 6, "forbidden")

            await usb.set({"sys.wifi_ssid": "IoT", "sys.wifi_pass": "secret"})
            check(await usb.get("sys.wifi_ssid") == "IoT", "ssid set over usb")

            await usb.trigger("sys.reboot")
            await usb.ping()
            check(await net.get("sys.ip") == "127.0.0.1", "single get")

            # a paired host can't pair somebody else over the network
            other = HostIdentity.create()
            try:
                await net._request(0x06, other.public)
                check(False, "PAIR over the network accepted")
            except SmartError as err:
                check(err.code == 6, f"PAIR forbidden on the network: {err}")

            # unpairing itself: the device hangs up and won't take it back
            await net.unpair(me.public)
            await asyncio.wait_for(net.closed.wait(), 2)
            await expect_error(emu.net(me), RejectedError, 1, "unpaired host comes back")
        finally:
            await net.close()
            await usb.close()


async def run_pairing_window(emulator: str) -> None:
    async with Emulator(emulator, pairing_seconds=30) as emu:
        owner, intruder = HostIdentity.create(), HostIdentity.create()

        dev = await emu.net(owner, pairing=True)
        check(owner.devices == {dev.info.device_id: dev.peer_key}, "paired over the window")
        # the window is the owner's consent: it may commission the device (Wi-Fi) from here
        await dev.set({"sys.wifi_ssid": "Home", "sys.wifi_pass": "secret"})
        check(await dev.get("sys.wifi_ssid") == "Home", "LOCAL allowed for the window's host")
        await dev.close()
        dev = await emu.net(owner)  # the owner comes back as a normal paired host
        await dev.close()

        # a second new host in the same window: conflict, and the owner is thrown out too
        await expect_error(emu.net(intruder, pairing=True), RejectedError, 2, "conflict")
        await expect_error(emu.net(owner), RejectedError, 1, "first host undone by the conflict")
        await asyncio.sleep(0.1)
        check("PAIRING opened" in emu.lines and "PAIRING paired" in emu.lines and "PAIRING conflict" in emu.lines,
              f"pairing events: {emu.lines}")


async def run_serial(emulator: str) -> None:
    """Serial transport through a pseudo-terminal bridged to the emulator (POSIX only).

    The bridge plays a board that reboots when the port opens: it prints a
    boot log and ignores input for the first second, so HELLO must be retried.
    """
    import os
    import pty
    import socket
    import threading
    import time
    import tty

    master, slave = pty.openpty()
    tty.setraw(slave)
    sock = None
    try:
        async with Emulator(emulator) as emu:
            # the bridge is the emulator's trusted "USB" side
            sock = socket.create_connection(("127.0.0.1", emu.port), source_address=("127.0.0.2", 0))
            booted_at = time.monotonic() + 1.0

            def host_to_device() -> None:
                with contextlib.suppress(OSError):
                    while data := os.read(master, 256):
                        if time.monotonic() >= booted_at:  # still booting: input is lost
                            sock.sendall(data)

            def device_to_host() -> None:
                with contextlib.suppress(OSError):
                    os.write(master, b"ESP-ROM:esp32c3-api1-20210207\r\nboot: log noise \xff\r\n")
                    while data := sock.recv(256):
                        os.write(master, data)

            for fn in (host_to_device, device_to_host):
                threading.Thread(target=fn, daemon=True).start()

            start = time.monotonic()
            dev = await connect(f"serial:{os.ttyname(slave)}")
            try:
                check(time.monotonic() - start >= 1.0, "HELLO retried until the board booted")
                check(dev.info.model == "lumenc3" and not dev.secure, "info over serial")
                await dev.set({"light.brightness": 42})
                check(await dev.get("light.brightness") == 42, "set/get over serial")
                # pairing over the serial port, then the network works
                me = HostIdentity.create()
                await dev.pair(me)
                net = await connect(f"tcp:127.0.0.1:{emu.port}", me)
                check(net.values["light.brightness"] == 42, "same device over the network")
                await net.close()
            finally:
                await dev.close()
    finally:
        if sock:
            sock.close()
        os.close(master)
        os.close(slave)


async def run_ota(emulator: str) -> None:
    """Images signed in Python (smartsign) checked and installed by the C core."""
    import hashlib
    import os

    import smartsign

    seed, other = os.urandom(32), os.urandom(32)
    pub = smartsign.public_key(seed)
    firmware = os.urandom(20000)
    async with Emulator(emulator, env=dict(os.environ, SMART_OTA_KEY=pub.hex())) as emu:
        usb = await emu.usb()
        me = HostIdentity.create()
        await usb.pair(me)
        net = await emu.net(me)
        try:
            check(net.info.ota and net.info.max_payload == 240, f"INFO: {net.info}")
            for image, what in ((smartsign.sign(firmware, other, 1, 2), "another key"),
                                (smartsign.sign(firmware, seed, 2, 2), "another model"),
                                (smartsign.sign(firmware, seed, 1, 1), "older security version")):
                try:
                    await net.update(image)
                    check(False, f"image with {what} installed")
                except SmartError as err:
                    check(err.code == 9, f"{what}: {err}")

            good = smartsign.sign(firmware, seed, 1, 2, "2.1.0")
            done = []
            await net.update(good, lambda d, t: done.append((d, t)))
            await asyncio.sleep(0.1)
            want = f"OTA installed {len(good)} {hashlib.sha512(firmware).hexdigest()[:16]}"
            check(want in emu.lines, f"installed: {emu.lines}")
            check(done[-1] == (len(firmware), len(firmware)), "progress reaches 100%")
            check(all(a[0] <= b[0] for a, b in zip(done, done[1:])), "progress never goes back")

            # smartsign itself: round trip, and tampering after signing is caught
            check(smartsign.verify(good, pub).version == "2.1.0", "verify")
            tampered = bytearray(good)
            tampered[100] ^= 1
            for bad, what in ((bytes(tampered), "tampered"), (good, "wrong key")):
                try:
                    smartsign.verify(bad, smartsign.public_key(other) if what == "wrong key" else pub)
                    check(False, f"{what} image verified")
                except smartsign.SignError:
                    pass
        finally:
            await net.close()
            await usb.close()


async def run_targets(emulator: str) -> None:
    async with Emulator(emulator) as emu:
        await expect_error(connect(f"tcp:127.0.0.1:{emu.port}"), SmartError, None, "tcp without identity")
        for bad in ("COM5", "usb:COM5", "tcp:", "serial:"):
            await expect_error(connect(bad), SmartError, None, f"bad target {bad!r}")


if __name__ == "__main__":
    test_framing()
    asyncio.run(run(sys.argv[1]))
    asyncio.run(run_pairing_window(sys.argv[1]))
    asyncio.run(run_ota(sys.argv[1]))
    asyncio.run(run_targets(sys.argv[1]))
    if sys.platform != "win32":
        asyncio.run(run_serial(sys.argv[1]))
    print("client tests passed")
