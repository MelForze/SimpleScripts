#!/usr/bin/env python3
"""Decode base64-encoded NTLMSSP messages from stdin, a file, or a direct argument."""

from __future__ import annotations

import argparse
import base64
import binascii
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


def create_argument_parser(*args, **kwargs) -> argparse.ArgumentParser:
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


FLAGS_TBL_STR = """0x00000001\tNegotiate Unicode
0x00000002\tNegotiate OEM
0x00000004\tRequest Target
0x00000008\tunknown
0x00000010\tNegotiate Sign
0x00000020\tNegotiate Seal
0x00000040\tNegotiate Datagram Style
0x00000080\tNegotiate Lan Manager Key
0x00000100\tNegotiate Netware
0x00000200\tNegotiate NTLM
0x00000400\tunknown
0x00000800\tNegotiate Anonymous
0x00001000\tNegotiate Domain Supplied
0x00002000\tNegotiate Workstation Supplied
0x00004000\tNegotiate Local Call
0x00008000\tNegotiate Always Sign
0x00010000\tTarget Type Domain
0x00020000\tTarget Type Server
0x00040000\tTarget Type Share
0x00080000\tNegotiate NTLM2 Key
0x00100000\tRequest Init Response
0x00200000\tRequest Accept Response
0x00400000\tRequest Non-NT Session Key
0x00800000\tNegotiate Target Info
0x01000000\tunknown
0x02000000\tunknown
0x04000000\tunknown
0x08000000\tunknown
0x10000000\tunknown
0x20000000\tNegotiate 128
0x40000000\tNegotiate Key Exchange
0x80000000\tNegotiate 56"""
FLAGS_TBL = [(int(flag, 16), description) for flag, description in (line.split("\t") for line in FLAGS_TBL_STR.splitlines())]

MSG_TYPES = {
    1: "Request",
    2: "Challenge",
    3: "Response",
}

TARGET_FIELD_TYPES = {
    0: "TERMINATOR",
    1: "Server name",
    2: "AD domain name",
    3: "FQDN",
    4: "DNS domain name",
    5: "Parent DNS domain",
    7: "Server Timestamp",
}
UTF16_AV_PAIR_TYPES = {1, 2, 3, 4, 5}


def flags_lst(flags: int) -> list[str]:
    return [desc for val, desc in FLAGS_TBL if val & flags]


def flags_str(flags: int) -> str:
    return ", ".join(f'"{value}"' for value in flags_lst(flags))


def clean_str(value: str | bytes | bytearray) -> str:
    """Return a printable representation while keeping printable Unicode intact."""
    if isinstance(value, (bytes, bytearray)):
        text = value.decode("latin-1", errors="replace")
    else:
        text = value
    return "".join(ch if ch.isprintable() and ch not in "\r\n\t\x0b\x0c" else "?" for ch in text)


def decode_best_effort(raw: bytes) -> tuple[str, bool]:
    if not raw:
        return "", False

    if len(raw) % 2 == 0 and any(raw[index] == 0 for index in range(1, len(raw), 2)):
        try:
            return raw.decode("utf-16le"), True
        except UnicodeDecodeError:
            pass
    return raw.decode("latin-1", errors="replace"), False


@dataclass(frozen=True, slots=True)
class StrStruct:
    length: int
    alloc: int
    offset: int
    raw: bytes
    string: str
    utf16: bool

    @classmethod
    def from_header(cls, pos_tup: tuple[int, int, int], payload: bytes) -> "StrStruct":
        length, alloc, offset = pos_tup
        if offset < 0:
            raise ValueError("Negative buffer offset.")
        data = payload[offset : offset + length]
        string, utf16 = decode_best_effort(data)
        return cls(length, alloc, offset, data, string, utf16)

    def __str__(self) -> str:
        display = "%s'%s' [%s] (%db @%d)" % (
            "u" if self.utf16 else "",
            clean_str(self.string),
            self.raw.hex(),
            self.length,
            self.offset,
        )
        if self.alloc != self.length:
            display += f" alloc: {self.alloc}"
        return display


def safe_unpack(fmt: str, data: bytes, offset: int) -> tuple | None:
    size = struct.calcsize(fmt)
    if len(data) < offset + size:
        return None
    return struct.unpack(fmt, data[offset : offset + size])


def read_security_buffer(data: bytes, offset: int) -> StrStruct | None:
    header = safe_unpack("<HHI", data, offset)
    if header is None:
        return None
    return StrStruct.from_header(header, data)


def format_optional_str(name: str, data: bytes, offset: int) -> str:
    struct_value = read_security_buffer(data, offset)
    if struct_value is None:
        return f"{name}: [omitted]"
    return f"{name}: {struct_value}"


def format_optional_inline(name: str, data: bytes, offset: int, size: int) -> str:
    chunk = data[offset : offset + size]
    if len(chunk) != size:
        return f"{name}: [omitted]"
    return f"{name}: '{clean_str(chunk)}'"


def decode_target_info_entry(rec_type_id: int, raw_value: bytes) -> str:
    if rec_type_id in UTF16_AV_PAIR_TYPES:
        try:
            return clean_str(raw_value.decode("utf-16le"))
        except UnicodeDecodeError:
            return clean_str(raw_value)
    if rec_type_id == 7:
        return raw_value.hex()
    return clean_str(raw_value)


def format_target_info_lines(target_info: StrStruct) -> list[str]:
    lines = [f"Target: [block] ({target_info.length}b @%d)" % target_info.offset]
    if target_info.alloc != target_info.length:
        lines[0] += f" alloc: {target_info.alloc}"

    raw = target_info.raw
    pos = 0
    while pos + 4 <= len(raw):
        rec_hdr = safe_unpack("<HH", raw, pos)
        if rec_hdr is None:
            break
        rec_type_id, rec_size = rec_hdr
        rec_type = TARGET_FIELD_TYPES.get(rec_type_id, "UNKNOWN")
        if rec_size < 0 or pos + 4 + rec_size > len(raw):
            lines.append("    [truncated target info]")
            break
        if rec_type_id == 0:
            lines.append(f"    {rec_type} ({rec_type_id})")
            break
        raw_value = raw[pos + 4 : pos + 4 + rec_size]
        lines.append(
            f"    {rec_type} ({rec_type_id}): {decode_target_info_entry(rec_type_id, raw_value)}"
        )
        pos += 4 + rec_size
    return lines


def pretty_print_request(data: bytes) -> list[str]:
    flags_tup = safe_unpack("<I", data, 12)
    if flags_tup is None:
        return ["Request message is truncated before flags"]

    flags = flags_tup[0]
    return [
        format_optional_str("Domain", data, 16),
        format_optional_str("Workstation", data, 24),
        format_optional_inline("OS Ver", data, 32, 8),
        f"Flags: 0x{flags:08x} [{flags_str(flags)}]",
    ]


def pretty_print_challenge(data: bytes) -> list[str]:
    target_name = read_security_buffer(data, 12)
    flags_tup = safe_unpack("<I", data, 20)
    challenge_tup = safe_unpack("<Q", data, 24)
    if target_name is None or flags_tup is None or challenge_tup is None:
        return ["Challenge message is truncated"]

    flags = flags_tup[0]
    challenge = challenge_tup[0]
    lines = [
        f"Target Name: {target_name}",
        f"Challenge: 0x{challenge:016x}",
    ]

    context = data[32:40]
    if len(context) == 8:
        lines.append(f"Context: {context.hex()}")
    else:
        lines.append("Context: [omitted]")

    target_info = read_security_buffer(data, 40)
    if target_info is None:
        lines.append("Target: [omitted]")
    else:
        lines.extend(format_target_info_lines(target_info))

    lines.append(format_optional_inline("OS Ver", data, 48, 8))
    lines.append(f"Flags: 0x{flags:08x} [{flags_str(flags)}]")
    return lines


def pretty_print_response(data: bytes) -> list[str]:
    lm_resp = read_security_buffer(data, 12)
    ntlm_resp = read_security_buffer(data, 20)
    target_name = read_security_buffer(data, 28)
    user_name = read_security_buffer(data, 36)
    host_name = read_security_buffer(data, 44)
    session_key = read_security_buffer(data, 52)
    if None in (lm_resp, ntlm_resp, target_name, user_name, host_name, session_key):
        return ["Response message is truncated"]

    flags_tup = safe_unpack("<I", data, 60)
    lines = [
        f"LM Resp: {lm_resp}",
        f"NTLM Resp: {ntlm_resp}",
        f"Target Name: {target_name}",
        f"User Name: {user_name}",
        f"Host Name: {host_name}",
        f"Session Key: {session_key}",
        format_optional_inline("OS Ver", data, 64, 8),
    ]
    if flags_tup is not None:
        flags = flags_tup[0]
        lines.append(f"Flags: 0x{flags:08x} [{flags_str(flags)}]")
    else:
        lines.append("Flags: [omitted]")
    return lines


def decode_ntlm_blob(blob: str) -> list[str]:
    normalized = blob.strip()
    if not normalized:
        raise ValueError("Input is empty.")

    try:
        data = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Input is not a valid base64-encoded string.") from exc

    if len(data) < 12:
        raise ValueError("NTLM message is too short.")
    if data[:8] != b"NTLMSSP\0":
        raise ValueError("NTLMSSP header not found at start of input string.")

    message_type_tup = safe_unpack("<I", data, 8)
    if message_type_tup is None:
        raise ValueError("NTLM message type is missing.")
    message_type = message_type_tup[0]

    lines = [
        "Found NTLMSSP header",
        f"Msg Type: {message_type} ({MSG_TYPES.get(message_type, 'UNKNOWN')})",
    ]
    if message_type == 1:
        lines.extend(pretty_print_request(data))
    elif message_type == 2:
        lines.extend(pretty_print_challenge(data))
    elif message_type == 3:
        lines.extend(pretty_print_response(data))
    else:
        lines.append("Unknown message structure. Have a raw (hex-encoded) message:")
        lines.append(data.hex())
    return lines


def extract_blobs(text: str) -> list[str]:
    blobs = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not blobs:
        raise ValueError("Input is empty.")
    return blobs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        prog="ntlmdecoder.py",
        description="Decode base64-encoded NTLMSSP blobs from stdin, a file, or a direct argument.",
        epilog=(
            "Examples:\n"
            "  echo 'TlRMTV...' | ntlmdecoder.py\n"
            "  ntlmdecoder.py -b TlRMTV...\n"
            "  ntlmdecoder.py -i ntlm_blobs_base64.txt"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-b", "--blob", help="Base64-encoded NTLMSSP blob.")
    source.add_argument("-i", "--input", type=Path, help="Path to a file with one or more blobs.")
    return parser.parse_args(argv)


def load_blobs(args: argparse.Namespace, stdin_text: str | None = None) -> list[str]:
    if args.blob is not None:
        return extract_blobs(args.blob)
    if args.input is not None:
        try:
            return extract_blobs(args.input.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ValueError(f"Error reading input file: {exc}") from exc

    return extract_blobs(sys.stdin.read() if stdin_text is None else stdin_text)


def render_blob_outputs(blobs: list[str]) -> list[str]:
    rendered: list[str] = []
    multiple = len(blobs) > 1
    for index, blob in enumerate(blobs, 1):
        if multiple:
            rendered.append(f"== Blob {index} ==")
        rendered.extend(decode_ntlm_blob(blob))
        if multiple and index != len(blobs):
            rendered.append("")
    return rendered


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        blobs = load_blobs(args)
        for line in render_blob_outputs(blobs):
            print(line)
        return 0
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
