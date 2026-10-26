# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 siakinnik
"""Cross-check our Noise_XX initiator (clients/python) against an independent
implementation, the `noiseprotocol` package, acting as the responder.

The C responder is already checked against our Python initiator in
test_client.py, so together this pins both halves to the specification.

    pip install noiseprotocol
    python3 test_noise_interop.py        (skips if the package is missing)
"""

import os
import sys

from smart_client import PROLOGUE, CipherState, NoiseXXInitiator, _x25519_public


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def main() -> int:
    try:
        from noise.connection import Keypair, NoiseConnection
    except ImportError:
        print("noiseprotocol not installed: skipped")
        return 0

    for payloads in ((b"", b"", b""), (b"hello", b"device says hi", b"3"), (b"x" * 100, b"", b"y" * 200)):
        i_static, r_static = os.urandom(32), os.urandom(32)

        responder = NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_BLAKE2b")
        responder.set_as_responder()
        responder.set_prologue(PROLOGUE)
        responder.set_keypair_from_private_bytes(Keypair.STATIC, r_static)
        responder.start_handshake()

        ours = NoiseXXInitiator(i_static)
        check(responder.read_message(ours.write1(payloads[0])) == payloads[0], "message 1 payload")
        check(ours.read2(responder.write_message(payloads[1])) == payloads[1], "message 2 payload")
        check(ours.rs == _x25519_public(r_static), "responder's static key learned")
        msg3, send, recv = ours.write3(payloads[2])
        check(responder.read_message(msg3) == payloads[2], "message 3 payload")
        check(responder.handshake_finished, "handshake finished")

        for i in range(3):
            data = os.urandom(10 + i * 50)
            check(responder.decrypt(send.encrypt(data)) == data, "initiator -> responder")
            check(recv.decrypt(responder.encrypt(data)) == data, "responder -> initiator")
        check(isinstance(send, CipherState) and send.n == 3 and recv.n == 3, "nonces advance")

    print("noise interop passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
