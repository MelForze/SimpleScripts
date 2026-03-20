#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


MAX_EXPANDABLE_ADDRESSES = 4096


def is_public_ip(ip: str) -> bool:
    """Check whether the given address is globally routable."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global and not ip_obj.is_multicast
    except ValueError:
        return False


def iter_network_hosts(network):
    """Iterate host addresses without including IPv4 network/broadcast."""
    if isinstance(network, ipaddress.IPv4Network):
        return network.hosts()
    return iter(network)


def process_line_as_network(line: str) -> list[str]:
    """Process a network and return globally routable host addresses."""
    try:
        network = ipaddress.ip_network(line, strict=False)
    except ValueError:
        return []

    if network.num_addresses > MAX_EXPANDABLE_ADDRESSES:
        return []

    public_ips = [str(ip) for ip in iter_network_hosts(network) if is_public_ip(str(ip))]
    return public_ips


def sort_ip_strings(ips: list[str]) -> list[str]:
    return sorted(
        set(ips),
        key=lambda value: (
            ipaddress.ip_address(value).version,
            int(ipaddress.ip_address(value)),
        ),
    )


def find_public_ips(input_file: Path) -> list[str] | None:
    """Find all globally routable IP addresses from the input file."""
    public_ips: list[str] = []
    try:
        with input_file.expanduser().open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                if is_public_ip(line):
                    public_ips.append(str(ipaddress.ip_address(line)))
                    continue

                public_ips.extend(process_line_as_network(line))
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        return None
    except OSError as exc:
        print(f"Error reading file '{input_file}': {exc}", file=sys.stderr)
        return None

    return sort_ip_strings(public_ips)


def print_to_console(ips: list[str]) -> None:
    """Print IPs to the console."""
    if ips:
        print("Public IP addresses:")
        for ip in ips:
            print(ip)


def save_to_file(output_file: Path, ips: list[str]) -> bool:
    """Save the public IP addresses to a file."""
    try:
        with output_file.expanduser().open("w", encoding="utf-8") as handle:
            for ip in ips:
                handle.write(f"{ip}\n")
    except OSError as exc:
        print(f"Error writing to file '{output_file}': {exc}", file=sys.stderr)
        return False

    print(f"Public IP addresses have been written to '{output_file}'")
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        description=(
            "Extract public IP addresses from a file, including expanding "
            "small subnets into host IPs."
        )
    )
    parser.add_argument("-i", "--input", help="Input file with IP addresses or networks")
    parser.add_argument(
        "-o",
        "--output",
        help="Optional output file. If omitted, results are printed to stdout.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input:
        print("Error: provide -i/--input.", file=sys.stderr)
        return 1

    public_ips = find_public_ips(Path(args.input))
    if public_ips is None:
        return 1
    if not public_ips:
        print("No public IP addresses were found.", file=sys.stderr)
        return 1

    if args.output:
        if not save_to_file(Path(args.output), public_ips):
            return 1
    else:
        print_to_console(public_ips)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
