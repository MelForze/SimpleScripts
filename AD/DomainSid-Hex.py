#!/usr/bin/env python3
"""
SID Converter Script

This script converts a Domain SID from its standard string format to a
hexadecimal representation.
"""

import argparse
import shutil
import subprocess
import sys


GREEN = "\033[1;92m"
MAX_IDENTIFIER_AUTHORITY = (1 << 48) - 1
MAX_SUB_AUTHORITY = (1 << 32) - 1
RESET = "\033[0m"


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def parse_int_in_range(value: str, label: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise ValueError(f"Invalid {label}: {value}") from exc

    if not (minimum <= parsed <= maximum):
        raise ValueError(
            f"{label.capitalize()} out of range: {value} "
            f"(expected {minimum}..{maximum})"
        )

    return parsed


def parse_sid_components(sid: str):
    items = sid.strip().split("-")
    if len(items) < 4 or items[0] != "S":
        raise ValueError(
            "Invalid SID format. It should start with 'S-' and contain at least 4 parts."
        )

    revision = parse_int_in_range(items[1], "revision", 0, 255)
    identifier_authority = parse_int_in_range(
        items[2],
        "identifier authority",
        0,
        MAX_IDENTIFIER_AUTHORITY,
    )

    sub_authorities = []
    for raw_value in items[3:]:
        sub_authorities.append(
            parse_int_in_range(
                raw_value,
                "sub-authority",
                0,
                MAX_SUB_AUTHORITY,
            )
        )

    if len(sub_authorities) > 255:
        raise ValueError("SID contains too many sub-authorities.")

    return revision, identifier_authority, sub_authorities


def convert_sid_to_hex(sid: str) -> str:
    revision, identifier_authority, sub_authorities = parse_sid_components(sid)

    sid_bytes = bytearray()
    sid_bytes.append(revision)
    sid_bytes.append(len(sub_authorities))
    sid_bytes.extend(identifier_authority.to_bytes(6, byteorder="big"))

    for sub_authority in sub_authorities:
        sid_bytes.extend(sub_authority.to_bytes(4, byteorder="little"))

    return "0x" + sid_bytes.hex().upper()


def build_parser() -> argparse.ArgumentParser:
    parser = create_argument_parser(
        description="Convert SID from string format to hexadecimal.",
        add_help=False,
    )
    parser.add_argument(
        "-s",
        "--sid",
        type=str,
        help=(
            "Domain SID in standard format "
            "(e.g. S-1-5-21-1154311717-913441446-2400334863-1114)"
        ),
    )
    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        help="Show this help message and exit.",
    )
    return parser


def clipboard_commands() -> list[list[str]]:
    commands = []
    candidates = [
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["clip.exe"],
        ["clip"],
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Set-Clipboard -Value ([Console]::In.ReadToEnd())",
        ],
    ]
    for command in candidates:
        if shutil.which(command[0]):
            commands.append(command)
    return commands


def copy_to_clipboard(text: str) -> bool:
    for command in clipboard_commands():
        try:
            completed = subprocess.run(
                command,
                input=text,
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError:
            continue
        if completed.returncode == 0:
            return True
    return False


def print_green_status(message: str) -> None:
    print(f"{GREEN}{message}{RESET}", file=sys.stderr, flush=True)


def main(argv=None) -> int:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if not argv_list:
        parser.print_help(sys.stderr)
        return 1

    args = parser.parse_args(argv_list)

    if args.help:
        parser.print_help()
        return 0
    if not args.sid:
        print("Error: The SID argument is required.", file=sys.stderr)
        return 1

    try:
        result = convert_sid_to_hex(args.sid)
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    if copy_to_clipboard(result):
        print_green_status("Result copied to clipboard.")
    else:
        print(
            "Warning: clipboard tool not found or copy failed; result printed to stdout.",
            file=sys.stderr,
            flush=True,
        )

    print(f"[+] SID: {args.sid}")
    print(f"[+] Result: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
