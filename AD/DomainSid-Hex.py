#!/usr/bin/env python3
"""
SID Converter Script

This script converts a Domain SID from its standard string format to a hexadecimal representation.

Usage:
    python3 ScriptName.py -s S-1-5-21-1154311717-913441446-2400334863-1114
"""

import sys
import argparse
from struct import pack
from typing import Any


def convert_sid_to_hex(sid: str) -> str:
    """
    Convert a SID string to its hexadecimal representation.
    """
    items = sid.split('-')
    if len(items) < 4 or items[0] != "S":
        raise ValueError("Invalid SID format. It should start with 'S' and contain at least 4 parts.")
    
    try:
        revision = pack('B', int(items[1]))
        dash_number = pack('B', len(items) - 3)
        identifier_authority = b'\x00\x00' + pack('>L', int(items[2]))
    except Exception as e:
        raise ValueError("Error processing SID components. Please check the input format.") from e

    sub_authority = b''
    try:
        for i in range(len(items) - 3):
            sub_authority += pack('<L', int(items[i + 3]))
    except Exception as e:
        raise ValueError("Error processing sub-authority values.") from e

    hex_sid = revision + dash_number + identifier_authority + sub_authority
    return '0x' + ''.join('{:02X}'.format(b) for b in hex_sid)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Convert SID from string format to hexadecimal."
    )
    parser.add_argument(
        "-s", "--sid",
        type=str,
        help="Domain SID in standard format (e.g. S-1-5-21-1154311717-913441446-2400334863-1114)"
    )
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    return parser.parse_args()


def main() -> None:
    """
    Main function that handles argument parsing, SID conversion, and result output.
    """
    args: argparse.Namespace = parse_arguments()
    if not args.sid:
        print("Error: The SID argument is required.")
        sys.exit(1)
    sid: str = args.sid
    print(f"[+] SID: {sid}")
    try:
        result: str = convert_sid_to_hex(sid)
        print(f"[+] Result: {result}")
    except ValueError as err:
        print(f"Error: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
