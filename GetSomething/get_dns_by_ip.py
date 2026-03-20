#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
from pathlib import Path


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def normalize_ip(ip_address: str) -> str:
    return str(ipaddress.ip_address(ip_address.strip()))


def get_dns_name(ip_address: str) -> str:
    """Get the DNS name for a given IP address."""
    try:
        dns_name, _, _ = socket.gethostbyaddr(ip_address)
        return dns_name
    except (socket.herror, socket.gaierror, OSError):
        return "DNS unreachable"


def format_result_line(ip_address: str) -> str:
    return f"{ip_address} - {get_dns_name(ip_address)}"


def write_results(results: list[str], output_file: Path | None = None) -> int:
    if not results:
        print("No valid IP addresses to process.", file=sys.stderr)
        return 1

    if output_file is None:
        for result_line in results:
            print(result_line)
        return 0

    try:
        with output_file.expanduser().open("w", encoding="utf-8") as handle:
            for result_line in results:
                handle.write(result_line + "\n")
    except OSError as exc:
        print(f"Error writing to file '{output_file}': {exc}", file=sys.stderr)
        return 1
    return 0


def process_ip(ip_address: str, output_file: str | None = None) -> int:
    """Process a single IP address, resolving it to a DNS name."""
    try:
        normalized_ip = normalize_ip(ip_address)
    except ValueError:
        print(f"Error: invalid IP address '{ip_address}'.", file=sys.stderr)
        return 1

    output_path = Path(output_file) if output_file else None
    return write_results([format_result_line(normalized_ip)], output_path)


def process_ip_file(input_file: str, output_file: str | None = None) -> int:
    """Process a file of IP addresses, resolving each to a DNS name."""
    input_path = Path(input_file).expanduser()
    try:
        with input_path.open("r", encoding="utf-8") as handle:
            results: list[str] = []
            for line in handle:
                raw_ip = line.strip()
                if not raw_ip:
                    continue
                try:
                    normalized_ip = normalize_ip(raw_ip)
                except ValueError:
                    print(f"Invalid IP address: {raw_ip}", file=sys.stderr)
                    continue
                results.append(format_result_line(normalized_ip))
    except OSError as exc:
        print(f"Error reading input file '{input_path}': {exc}", file=sys.stderr)
        return 1

    output_path = Path(output_file) if output_file else None
    return write_results(results, output_path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        description="Resolve DNS names for a single IP address or a file of IP addresses."
    )
    parser.add_argument("-a", "--address", help="Single IP address to resolve.")
    parser.add_argument("-i", "--input", help="Input file containing IP addresses.")
    parser.add_argument(
        "-o",
        "--output",
        help="Optional output file. If omitted, results are printed to stdout.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if not args.address and not args.input:
        print("Error: provide -a/--address or -i/--input.", file=sys.stderr)
        return 1
    if args.address and args.input:
        print("Error: use either -a/--address or -i/--input, not both.", file=sys.stderr)
        return 1

    if args.address:
        return process_ip(args.address, args.output)
    return process_ip_file(args.input, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
