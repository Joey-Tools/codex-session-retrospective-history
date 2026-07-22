#!/usr/bin/env python3
from __future__ import annotations

import re


OPENPGP_SECRET_KEY_PACKET_TAGS = frozenset({5, 7})
OPENPGP_KEY_PACKET_VERSIONS = frozenset({2, 3, 4, 5, 6})
OPENPGP_KEY_PACKET_PREFIX_BYTES = 8
MAX_OPENPGP_PARTIAL_BODY_CHUNKS = 64


HIGH_CONFIDENCE_CREDENTIAL_PATTERNS = (
    re.compile(
        b"-----BEGIN "
        + b"(?:OPENSSH |PGP |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY"
        + b"(?: BLOCK)?-----",
        re.I,
    ),
    re.compile(
        rb"(?<![A-Za-z0-9_.-])[\"']?Authorization[\"']?[ \t]*(?::|=)[ \t]*"
        rb"[\"']?Bearer[ \t]+"
        rb"[A-Za-z0-9._~+/-]{16,4096}={0,2}"
        rb"(?![A-Za-z0-9._~+/=-])(?=[ \t]*(?:\r?$|[\"'\]\\},;]))",
        re.I | re.M,
    ),
    re.compile(
        rb"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9_]{24,}|"
        rb"github_pat_[A-Za-z0-9_]{40,})(?![A-Za-z0-9_])"
    ),
    re.compile(
        rb"(?<![A-Za-z0-9_-])(?:sk|rk)[-_](?:proj[-_])?[A-Za-z0-9_-]{24,}"
        rb"(?![A-Za-z0-9_-])"
    ),
    re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    re.compile(
        rb"(?<![A-Za-z0-9-])xox[A-Za-z0-9]{1,8}-[A-Za-z0-9-]{20,}"
        rb"(?![A-Za-z0-9-])",
        re.I,
    ),
    re.compile(rb"(?<![A-Za-z0-9_])sk_live_[A-Za-z0-9]{24,}"),
    re.compile(rb"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    re.compile(
        rb"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}"
        rb"(?![A-Za-z0-9_-])"
    ),
    re.compile(rb"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_])"),
)


class _OpenPGPPartialBodyError(ValueError):
    pass


def _openpgp_new_packet_length(
    payload: bytes, offset: int
) -> tuple[int, int, bool] | None:
    if offset >= len(payload):
        return None
    first = payload[offset]
    offset += 1
    if first < 192:
        return first, offset, False
    if first < 224:
        if offset >= len(payload):
            return None
        return ((first - 192) << 8) + payload[offset] + 192, offset + 1, False
    if first == 255:
        end = offset + 4
        if end > len(payload):
            return None
        return int.from_bytes(payload[offset:end], "big"), end, False
    return 1 << (first & 0x1F), offset, True


def _openpgp_partial_packet_body(
    payload: bytes, offset: int, first_length: int
) -> tuple[bytes, int]:
    prefix = bytearray()
    body_length = 0
    chunk_length = first_length

    for _chunk_index in range(MAX_OPENPGP_PARTIAL_BODY_CHUNKS):
        chunk_end = offset + chunk_length
        if chunk_end > len(payload):
            raise _OpenPGPPartialBodyError
        prefix.extend(
            payload[
                offset : min(
                    chunk_end, offset + OPENPGP_KEY_PACKET_PREFIX_BYTES - len(prefix)
                )
            ]
        )
        body_length += chunk_length
        offset = chunk_end

        decoded = _openpgp_new_packet_length(payload, offset)
        if decoded is None:
            raise _OpenPGPPartialBodyError
        chunk_length, offset, is_partial = decoded
        if is_partial:
            continue

        body_end = offset + chunk_length
        if body_end > len(payload):
            raise _OpenPGPPartialBodyError
        prefix.extend(
            payload[
                offset : min(
                    body_end, offset + OPENPGP_KEY_PACKET_PREFIX_BYTES - len(prefix)
                )
            ]
        )
        return bytes(prefix), body_length + chunk_length

    raise _OpenPGPPartialBodyError


def _openpgp_secret_packet_body(
    payload: bytes, offset: int
) -> tuple[bytes, int] | None:
    header = payload[offset]
    if header & 0x80 == 0:
        return None

    cursor = offset + 1
    if header & 0x40:
        tag = header & 0x3F
        if tag not in OPENPGP_SECRET_KEY_PACKET_TAGS:
            return None
        decoded = _openpgp_new_packet_length(payload, cursor)
        if decoded is None:
            return None
        body_length, cursor, is_partial = decoded
        if is_partial:
            return _openpgp_partial_packet_body(payload, cursor, body_length)
    else:
        tag = (header >> 2) & 0x0F
        if tag not in OPENPGP_SECRET_KEY_PACKET_TAGS:
            return None
        length_type = header & 0x03
        if length_type == 3:
            body_length = len(payload) - cursor
        else:
            length_octets = (1, 2, 4)[length_type]
            if cursor + length_octets > len(payload):
                return None
            body_length = int.from_bytes(
                payload[cursor : cursor + length_octets], "big"
            )
            cursor += length_octets

    body_end = cursor + body_length
    if body_length <= 0 or body_end > len(payload):
        return None
    return payload[
        cursor : min(body_end, cursor + OPENPGP_KEY_PACKET_PREFIX_BYTES)
    ], body_length


def contains_openpgp_secret_key_packet(payload: bytes) -> bool:
    """Detect framed binary OpenPGP Secret-Key and Secret-Subkey packets."""

    for offset, header in enumerate(payload):
        if header & 0x80 == 0:
            continue
        try:
            packet_body = _openpgp_secret_packet_body(payload, offset)
        except _OpenPGPPartialBodyError:
            return True
        if packet_body is None:
            continue
        body_prefix, body_length = packet_body
        version = body_prefix[0]
        minimum_body_length = 8 if version in {2, 3} else 6
        if (
            version in OPENPGP_KEY_PACKET_VERSIONS
            and body_length >= minimum_body_length
        ):
            return True
    return False


def contains_high_confidence_credential(payload: bytes) -> bool:
    return contains_openpgp_secret_key_packet(payload) or any(
        pattern.search(payload) for pattern in HIGH_CONFIDENCE_CREDENTIAL_PATTERNS
    )


__all__ = [
    "HIGH_CONFIDENCE_CREDENTIAL_PATTERNS",
    "contains_high_confidence_credential",
    "contains_openpgp_secret_key_packet",
]
