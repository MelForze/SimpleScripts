#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def extract_hashes_from_line(line: str) -> list[str]:
    """
    Extract one or more hashes from a shadow or opasswd line.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return []

    parts = line.split(":")
    if len(parts) > 2 and parts[1].startswith("$"):
        hash_field = parts[1]
    elif len(parts) >= 2:
        hash_field = parts[-1]
    else:
        return []

    return [value.strip() for value in hash_field.split(",") if value.strip()]


def extract_hashes_from_file(input_file: str | Path) -> list[str] | None:
    input_path = Path(input_file).expanduser()
    hashes: list[str] = []
    try:
        with input_path.open("r", encoding="utf-8") as input_handle:
            for line in input_handle:
                hashes.extend(extract_hashes_from_line(line))
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return None
    return hashes


def convert_mixed_file_to_hashes(
    input_file: str | Path,
    output_file: str | Path | None = None,
) -> int:
    """
    Read a file that may contain opasswd or shadow entries and output hashes
    in a Hashcat-friendly format.
    """
    hashes = extract_hashes_from_file(input_file)
    if hashes is None:
        return 1

    if not hashes:
        print("No hashes were found in the input file.", file=sys.stderr)
        return 1

    if output_file is None:
        for value in hashes:
            print(value)
        return 0

    output_path = Path(output_file).expanduser()
    try:
        with output_path.open("w", encoding="utf-8") as output_handle:
            for value in hashes:
                output_handle.write(value + "\n")
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Saved {len(hashes)} hashes to '{output_path.name}'")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        description="Extract shadow/opasswd hashes and save them in a Hashcat-friendly format."
    )
    parser.add_argument("-i", "--input", help="Input file containing shadow or opasswd data.")
    parser.add_argument(
        "-o",
        "--output",
        help="Optional output file. If omitted, hashes are printed to stdout.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input:
        print("Error: provide -i/--input.", file=sys.stderr)
        return 1
    return convert_mixed_file_to_hashes(args.input, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
