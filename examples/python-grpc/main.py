#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

"""Drive a running Basil agent from Python. No Basil client library needed.

The agent's Unix socket speaks standard gRPC, so any language with grpc +
protoc can talk to it. This script generates Python stubs at runtime from the
repo's canonical `broker.proto`, dials the socket, and exercises AdminService
`Status` plus SigningService `Sign`/`Verify`. Authorization needs no token:
the broker attests this process by its kernel-verified uid (`SO_PEERCRED`).

A packaged Python client library is on the roadmap; this shows the raw wire
surface it will wrap. Requires: pip install grpcio grpcio-tools
"""

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
# The canonical proto contract shared by the Rust and Go clients.
PROTO_ROOT = SCRIPT_DIR / ".." / ".." / "crates" / "basil-proto" / "proto"
GEN_DIR = Path(os.environ.get("BASIL_PYGRPC_GEN", SCRIPT_DIR / "gen"))

# The catalog key this script signs with; run.sh provisions it and grants this
# uid sign/verify/get_public_key on it.
KEY_ID = os.environ.get("BASIL_SIGNING_KEY_ID", "demo.signing_key")


def ensure_stubs() -> None:
    """Generate gRPC stubs into GEN_DIR if they are not already there.

    grpcio-tools bundles the well-known types (Duration/Timestamp) that
    broker.proto imports; google/rpc/status.proto ships in the repo's proto
    root and carries the broker's structured error details.
    """
    if (GEN_DIR / "basil" / "broker" / "v1" / "broker_pb2_grpc.py").exists():
        return
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            "-I",
            str(PROTO_ROOT.resolve()),
            f"--python_out={GEN_DIR}",
            f"--grpc_python_out={GEN_DIR}",
            "basil/broker/v1/broker.proto",
            "google/rpc/status.proto",
        ],
        check=True,
    )


def main() -> None:
    socket = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BASIL_SOCKET")
    if not socket:
        sys.exit("usage: main.py <agent-socket-path> (or set BASIL_SOCKET)")

    ensure_stubs()
    sys.path.insert(0, str(GEN_DIR))
    import grpc  # deferred: run.sh SKIPs cleanly when grpcio is missing
    from basil.broker.v1 import broker_pb2, broker_pb2_grpc

    # A plain insecure channel: the socket is local and the broker attests the
    # caller with SO_PEERCRED, so there is no TLS and no bearer token to wire.
    # Pin a syntactically valid HTTP/2 :authority otherwise the target (a
    # filesystem path) leaks into :authority and the broker resets the stream.
    channel = grpc.insecure_channel(
        f"unix://{Path(socket).resolve()}",
        options=[("grpc.default_authority", "localhost")],
    )

    # 1. AdminService.Status: prove we are speaking the broker protocol.
    admin = broker_pb2_grpc.AdminServiceStub(channel)
    status = admin.Status(broker_pb2.StatusRequest())
    print(
        f"PASS status backend={status.backend} version={status.version} "
        f"protocol={status.protocol}"
    )

    # 2. SigningService.Sign: the Ed25519 key signs IN PLACE in the backend;
    #    only the detached signature crosses the socket.
    signing = broker_pb2_grpc.SigningServiceStub(channel)
    message = b"python speaks basil's grpc natively"
    sig = signing.Sign(broker_pb2.SignRequest(key_id=KEY_ID, message=message))
    assert len(sig.signature) == 64, "expected a 64-byte Ed25519 signature"
    print(f"PASS sign {KEY_ID} signature_len={len(sig.signature)}")

    # 3. SigningService.Verify: the broker confirms the signature ...
    ok = signing.Verify(
        broker_pb2.VerifyRequest(
            key_id=KEY_ID, message=message, signature=sig.signature
        )
    )
    assert ok.valid, "broker reported the signature as INVALID"
    print("PASS verify valid=true")

    # ... and authoritatively rejects a one-bit tamper (valid=False is an
    # answer, not an error).
    tampered = bytes([message[0] ^ 1]) + message[1:]
    bad = signing.Verify(
        broker_pb2.VerifyRequest(
            key_id=KEY_ID, message=tampered, signature=sig.signature
        )
    )
    assert not bad.valid, "tampered message unexpectedly verified"
    print("PASS verify tampered=rejected")

    print("python-grpc: all assertions passed")


if __name__ == "__main__":
    main()
