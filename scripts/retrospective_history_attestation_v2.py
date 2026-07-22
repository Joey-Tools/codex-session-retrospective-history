#!/usr/bin/env python3
from __future__ import annotations

import base64
import binascii
import re


PUBLISHER_ATTESTATION_DOMAIN = b"session-retrospective-publisher-attestation-v2"
PUBLISHER_ATTESTATION_SCHEME = "openpgp-detached-v1"
RUN_REF_RE = re.compile(r"^run_ref_v2:[a-z2-7]{25}[aeimquy4]$")
BUNDLE_DIGEST_RE = re.compile(r"^retained_bundle_digest_v2:sha256:[0-9a-f]{64}$")
PUBLISHER_FINGERPRINT_RE = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")
ARMOR_BEGIN = b"-----BEGIN PGP SIGNATURE-----"
ARMOR_END = b"-----END PGP SIGNATURE-----"
ARMOR_PAYLOAD_RE = re.compile(rb"[A-Za-z0-9+/]{1,64}={0,2}")
ARMOR_CHECKSUM_RE = re.compile(rb"=[A-Za-z0-9+/]{4}")
MAX_PUBLISHER_SIGNATURE_BYTES = 16 * 1024
OPENPGP_SIGNATURE_PACKET_TAG = 2
OPENPGP_BINARY_DOCUMENT_SIGNATURE = 0
OPENPGP_SECURE_HASH_ALGORITHMS = frozenset({8, 9, 10, 11})
OPENPGP_SIGNATURE_MPI_COUNTS = {
    1: 1,  # RSA
    3: 1,  # RSA sign-only
    17: 2,  # DSA
    19: 2,  # ECDSA
    22: 2,  # EdDSA
}


class PublisherAttestationError(ValueError):
    pass


def _frame(frame_type: bytes, value: bytes) -> bytes:
    return frame_type + len(value).to_bytes(8, "big") + value


def publisher_attestation_payload(run_ref: str, bundle_digest: str) -> bytes:
    if RUN_REF_RE.fullmatch(run_ref) is None:
        raise ValueError("publisher attestation run_ref is invalid")
    if BUNDLE_DIGEST_RE.fullmatch(bundle_digest) is None:
        raise ValueError("publisher attestation bundle digest is invalid")
    return b"".join(
        (
            PUBLISHER_ATTESTATION_DOMAIN,
            _frame(b"R", run_ref.encode("ascii")),
            _frame(b"D", bundle_digest.encode("ascii")),
        )
    )


def _crc24(payload: bytes) -> bytes:
    crc = 0xB704CE
    for value in payload:
        crc ^= value << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return (crc & 0xFFFFFF).to_bytes(3, "big")


def _packet_length(raw: bytes, offset: int, first: int) -> tuple[int, int]:
    if first < 192:
        return first, offset
    if first < 224:
        if offset >= len(raw):
            raise PublisherAttestationError("truncated OpenPGP packet length")
        return ((first - 192) << 8) + raw[offset] + 192, offset + 1
    if first == 255:
        end = offset + 4
        if end > len(raw):
            raise PublisherAttestationError("truncated OpenPGP packet length")
        length = int.from_bytes(raw[offset:end], "big")
        if length < 8384:
            raise PublisherAttestationError("non-canonical OpenPGP packet length")
        return length, end
    raise PublisherAttestationError("partial OpenPGP packet lengths are not canonical")


def _signature_packet_body(packet: bytes) -> bytes:
    if not packet or packet[0] & 0x80 == 0:
        raise PublisherAttestationError("invalid OpenPGP packet header")
    first = packet[0]
    offset = 1
    if first & 0x40:
        tag = first & 0x3F
        if offset >= len(packet):
            raise PublisherAttestationError("truncated OpenPGP packet")
        length, offset = _packet_length(packet, offset + 1, packet[offset])
    else:
        tag = (first >> 2) & 0x0F
        length_type = first & 0x03
        length_bytes = (1, 2, 4, 0)[length_type]
        if not length_bytes or offset + length_bytes > len(packet):
            raise PublisherAttestationError("non-canonical OpenPGP packet length")
        length = int.from_bytes(packet[offset : offset + length_bytes], "big")
        if (length_type == 1 and length < 256) or (length_type == 2 and length < 65536):
            raise PublisherAttestationError("non-canonical OpenPGP packet length")
        offset += length_bytes
    if tag != OPENPGP_SIGNATURE_PACKET_TAG or offset + length != len(packet):
        raise PublisherAttestationError(
            "publisher attestation must contain one signature packet"
        )
    return packet[offset:]


def _subpacket_length(raw: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(raw):
        raise PublisherAttestationError("truncated OpenPGP signature subpacket")
    first = raw[offset]
    return _packet_length(raw, offset + 1, first)


def _signature_subpackets(raw: bytes) -> list[tuple[int, bool, bytes]]:
    subpackets: list[tuple[int, bool, bytes]] = []
    offset = 0
    while offset < len(raw):
        length, body_offset = _subpacket_length(raw, offset)
        end = body_offset + length
        if length < 1 or end > len(raw):
            raise PublisherAttestationError("invalid OpenPGP signature subpacket")
        type_octet = raw[body_offset]
        subpackets.append(
            (type_octet & 0x7F, bool(type_octet & 0x80), raw[body_offset + 1 : end])
        )
        offset = end
    return subpackets


def _validate_signature_mpis(raw: bytes, expected_count: int) -> None:
    offset = 0
    for _ in range(expected_count):
        if offset + 2 > len(raw):
            raise PublisherAttestationError("truncated OpenPGP signature MPI")
        bit_length = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        byte_length = (bit_length + 7) // 8
        end = offset + byte_length
        if bit_length == 0 or end > len(raw):
            raise PublisherAttestationError("invalid OpenPGP signature MPI")
        value = raw[offset:end]
        if int.from_bytes(value, "big").bit_length() != bit_length:
            raise PublisherAttestationError("non-canonical OpenPGP signature MPI")
        offset = end
    if offset != len(raw):
        raise PublisherAttestationError("extra OpenPGP signature packet bytes")


def _validate_signature_packet(packet: bytes, signer_fingerprint: str) -> None:
    body = _signature_packet_body(packet)
    if len(body) < 12 or body[0] != 4:
        raise PublisherAttestationError("only OpenPGP v4 signatures are accepted")
    if body[1] != OPENPGP_BINARY_DOCUMENT_SIGNATURE:
        raise PublisherAttestationError("publisher signature type is invalid")
    public_key_algorithm = body[2]
    if public_key_algorithm not in OPENPGP_SIGNATURE_MPI_COUNTS:
        raise PublisherAttestationError("publisher signature algorithm is invalid")
    if body[3] not in OPENPGP_SECURE_HASH_ALGORITHMS:
        raise PublisherAttestationError("publisher signature hash is invalid")

    hashed_length = int.from_bytes(body[4:6], "big")
    hashed_end = 6 + hashed_length
    if hashed_end + 2 > len(body):
        raise PublisherAttestationError("truncated hashed signature subpackets")
    unhashed_length = int.from_bytes(body[hashed_end : hashed_end + 2], "big")
    unhashed_start = hashed_end + 2
    unhashed_end = unhashed_start + unhashed_length
    if unhashed_end + 2 > len(body):
        raise PublisherAttestationError("truncated unhashed signature subpackets")

    fingerprint = bytes.fromhex(signer_fingerprint)
    fingerprint_version = 4 if len(fingerprint) == 20 else 5
    hashed = _signature_subpackets(body[6:hashed_end])
    unhashed = _signature_subpackets(body[unhashed_start:unhashed_end])
    if len(hashed) != 2 or {entry[0] for entry in hashed} != {2, 33}:
        raise PublisherAttestationError("hashed signature subpackets are not canonical")
    if any(critical for _tag, critical, _value in hashed):
        raise PublisherAttestationError(
            "critical signature subpackets are not accepted"
        )
    creation = next(value for tag, _critical, value in hashed if tag == 2)
    issuer_fingerprint = next(value for tag, _critical, value in hashed if tag == 33)
    if (
        len(creation) != 4
        or issuer_fingerprint != bytes((fingerprint_version,)) + fingerprint
    ):
        raise PublisherAttestationError("hashed signer binding is invalid")
    if unhashed != [(16, False, fingerprint[-8:])]:
        raise PublisherAttestationError("unhashed signer key ID is not canonical")

    _validate_signature_mpis(
        body[unhashed_end + 2 :],
        OPENPGP_SIGNATURE_MPI_COUNTS[public_key_algorithm],
    )


def canonical_openpgp_detached_signature(
    signature: str | bytes,
    signer_fingerprint: str,
) -> bytes:
    """Return canonical armor after validating every retained signature byte."""

    if PUBLISHER_FINGERPRINT_RE.fullmatch(signer_fingerprint) is None:
        raise PublisherAttestationError("publisher fingerprint is invalid")
    try:
        encoded = (
            signature.encode("ascii")
            if isinstance(signature, str)
            else bytes(signature)
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise PublisherAttestationError("publisher signature is not ASCII") from exc
    if not encoded or len(encoded) > MAX_PUBLISHER_SIGNATURE_BYTES or b"\r" in encoded:
        raise PublisherAttestationError("publisher signature armor is invalid")
    lines = encoded.split(b"\n")
    if (
        len(lines) < 6
        or lines[0] != ARMOR_BEGIN
        or lines[1] != b""
        or lines[-1] != ARMOR_END
        or ARMOR_CHECKSUM_RE.fullmatch(lines[-2]) is None
    ):
        raise PublisherAttestationError("publisher signature armor is not canonical")
    payload_lines = lines[2:-2]
    if not payload_lines or any(
        ARMOR_PAYLOAD_RE.fullmatch(line) is None for line in payload_lines
    ):
        raise PublisherAttestationError("publisher signature payload is invalid")
    joined = b"".join(payload_lines)
    try:
        packet = base64.b64decode(joined, validate=True)
        checksum = base64.b64decode(lines[-2][1:], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PublisherAttestationError(
            "publisher signature base64 is invalid"
        ) from exc
    canonical_payload = base64.b64encode(packet)
    canonical_lines = [
        canonical_payload[offset : offset + 64]
        for offset in range(0, len(canonical_payload), 64)
    ]
    if payload_lines != canonical_lines or checksum != _crc24(packet):
        raise PublisherAttestationError("publisher signature armor is not canonical")
    canonical = b"\n".join((ARMOR_BEGIN, b"", *canonical_lines, lines[-2], ARMOR_END))
    if canonical != encoded:
        raise PublisherAttestationError("publisher signature armor is not canonical")
    _validate_signature_packet(packet, signer_fingerprint)
    return canonical


__all__ = [
    "MAX_PUBLISHER_SIGNATURE_BYTES",
    "PUBLISHER_ATTESTATION_DOMAIN",
    "PUBLISHER_ATTESTATION_SCHEME",
    "PublisherAttestationError",
    "canonical_openpgp_detached_signature",
    "publisher_attestation_payload",
]
