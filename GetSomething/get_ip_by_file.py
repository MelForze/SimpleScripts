#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


CANDIDATE_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


def normalize_candidate(candidate: str) -> str | None:
    if "/" in candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def extract_ips(input_text: str) -> list[str]:
    """Extract valid IPv4 addresses from the input text."""
    found: list[str] = []
    for candidate in CANDIDATE_PATTERN.findall(input_text):
        normalized = normalize_candidate(candidate)
        if normalized is not None:
            found.append(normalized)
    return found


def sort_key(value: str):
    if "/" in value:
        network = ipaddress.ip_network(value, strict=False)
        return (1, network.version, int(network.network_address), network.prefixlen)

    address = ipaddress.ip_address(value)
    return (0, address.version, int(address), address.max_prefixlen)


def unique_ips(input_ips: list[str]) -> list[str]:
    """Remove duplicates and sort the list of IP addresses."""
    return sorted(set(input_ips), key=sort_key)


def save_to_file(output_file: Path, data: list[str]) -> bool:
    """Write data to the specified output file."""
    try:
        with output_file.expanduser().open("w", encoding="utf-8") as handle:
            for item in data:
                handle.write(f"{item}\n")
    except OSError as exc:
        print(f"Error writing to file '{output_file}': {exc}", file=sys.stderr)
        return False

    print(f"Unique IP addresses have been written to '{output_file}'")
    return True


def print_to_console(data: list[str]) -> None:
    """Print data to the console."""
    print("Unique IP addresses:")
    for item in data:
        print(item)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        description="Extract unique IPv4 addresses from a file."
    )
    parser.add_argument("-i", "--input", help="Input file path containing the data.")
    parser.add_argument(
        "-o",
        "--output",
        help="Optional output file path. If omitted, results are printed to stdout.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Main function to process IPs from an input file and save or print them."""
    args = parse_args(argv)
    if not args.input:
        print("Error: provide -i/--input.", file=sys.stderr)
        return 1

    input_file = Path(args.input).expanduser()
    try:
        with input_file.open("r", encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error reading file '{input_file}': {exc}", file=sys.stderr)
        return 1

    unique_ips_list = unique_ips(extract_ips(content))
    if not unique_ips_list:
        print("No IP addresses found in the input file.", file=sys.stderr)
        return 1

    if args.output:
        if not save_to_file(Path(args.output), unique_ips_list):
            return 1
    else:
        print_to_console(unique_ips_list)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
