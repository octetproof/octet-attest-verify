#!/usr/bin/env python3
"""Split a captured LocationProof into App Attest test-vector files.

A real attestation can only be produced on a physical device. Capture one
proof from an App-Attest-enabled build (the proof's serialized protobuf form),
then run this to drop attestation_object.bin / assertion.bin / meta.txt next to
this script so `cargo test` can run the full chain against Apple's root.

Usage:
    extract_vector.py <proof.b64 | -->  [--out DIR] [--team TEAM_ID] [--bundle BUNDLE_ID]

Input is base64 of the serialized LocationProof (the SDK's `proof.proofBytes`),
read from a file path or from stdin ("-"). team/bundle are NOT recoverable from
the proof (the appId is a one-way SHA256 hash), so pass them explicitly or fill
the TODO lines in meta.txt afterwards. The App Attest environment is detected
automatically from the attestation's AAGUID.

No external deps — minimal protobuf wire-format walk by field number.
"""
import base64
import sys
from pathlib import Path

# Wire field numbers (see octet/proof/proof.proto):
LOCATIONPROOF_DEVICE_ATTESTATION = 8   # message
DA_KEY_ID = 1                          # string
DA_APP_ATTEST_ATTESTATION = 8          # bytes (CBOR attestation object)
DA_APP_ATTEST_ASSERTION = 9            # bytes
DA_ATTESTATION_NONCE = 10              # bytes


def _read_varint(buf, i):
    shift = 0
    val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7


def parse_fields(buf):
    """Yield (field_number, wire_type, value_bytes_or_int) for one message."""
    i = 0
    n = len(buf)
    while i < n:
        tag, i = _read_varint(buf, i)
        field, wire = tag >> 3, tag & 0x07
        if wire == 0:        # varint
            val, i = _read_varint(buf, i)
            yield field, wire, val
        elif wire == 2:      # length-delimited
            ln, i = _read_varint(buf, i)
            yield field, wire, buf[i:i + ln]
            i += ln
        elif wire == 5:      # 32-bit
            yield field, wire, buf[i:i + 4]; i += 4
        elif wire == 1:      # 64-bit
            yield field, wire, buf[i:i + 8]; i += 8
        else:
            raise ValueError(f"unsupported wire type {wire} at field {field}")


def first(buf, target_field, target_wire=2):
    for field, wire, val in parse_fields(buf):
        if field == target_field and wire == target_wire:
            return val
    return None


def detect_env(attestation_object: bytes) -> str:
    # The AAGUID inside the attestation's authData is the literal ASCII tag
    # "appattestdevelop" (development) or "appattest\0\0\0\0\0\0\0" (production).
    if b"appattestdevelop" in attestation_object:
        return "development"
    if b"appattest" in attestation_object:
        return "production"
    return "unknown"


def main(argv):
    args = argv[1:]
    out = Path(__file__).parent
    team = bundle = None
    pos = []
    it = iter(range(len(args)))
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--out":
            out = Path(args[i + 1]); i += 2
        elif a == "--team":
            team = args[i + 1]; i += 2
        elif a == "--bundle":
            bundle = args[i + 1]; i += 2
        else:
            pos.append(a); i += 1
    if not pos:
        print(__doc__); return 2

    raw = sys.stdin.buffer.read() if pos[0] == "-" else Path(pos[0]).read_bytes()
    proof = base64.b64decode(b"".join(raw.split()))

    da = first(proof, LOCATIONPROOF_DEVICE_ATTESTATION)
    if da is None:
        print("ERROR: no device_attestation (field 8) in proof", file=sys.stderr)
        return 1

    attestation = first(da, DA_APP_ATTEST_ATTESTATION)
    assertion = first(da, DA_APP_ATTEST_ASSERTION)
    nonce = first(da, DA_ATTESTATION_NONCE)
    key_id_b64 = first(da, DA_KEY_ID, target_wire=2)

    missing = [n for n, v in [("app_attest_attestation(8)", attestation),
                              ("app_attest_assertion(9)", assertion),
                              ("attestation_nonce(10)", nonce)] if not v]
    if missing:
        print("ERROR: proof is missing App Attest field(s): " + ", ".join(missing),
              file=sys.stderr)
        print("  -> capture the FIRST proof of a fresh session (the window-opening "
              "proof carries the attestation object); later proofs reuse it.",
              file=sys.stderr)
        return 1

    out.mkdir(parents=True, exist_ok=True)
    (out / "attestation_object.bin").write_bytes(attestation)
    (out / "assertion.bin").write_bytes(assertion)

    key_id_hex = base64.b64decode(key_id_b64).hex() if key_id_b64 else ""
    env = detect_env(attestation)
    meta = [
        f"nonce_hex={nonce.hex()}",
        f"key_id_hex={key_id_hex}",
        f"team_id={team or '# TODO: fill the Apple Team ID'}",
        f"bundle_id={bundle or '# TODO: fill the app bundle id'}",
        f"env={env}",
    ]
    (out / "meta.txt").write_text("\n".join(meta) + "\n")

    print(f"wrote {out}/attestation_object.bin ({len(attestation)} bytes)")
    print(f"wrote {out}/assertion.bin ({len(assertion)} bytes)")
    print(f"wrote {out}/meta.txt (env={env}" +
          ("" if team and bundle else ", team_id/bundle_id need filling") + ")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
