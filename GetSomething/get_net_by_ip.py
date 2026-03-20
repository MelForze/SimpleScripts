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


DEFAULT_PREFIXLEN = {
    4: 24,
    6: 64,
}


def parse_ip_or_network(line: str):
    """
    Interpret a line as either a single IP address mapped to a default subnet
    size, or a CIDR network.
    """
    line = line.strip()
    if not line:
        return None

    try:
        ip = ipaddress.ip_address(line)
        prefixlen = DEFAULT_PREFIXLEN[ip.version]
        return ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
    except ValueError:
        pass

    try:
        return ipaddress.ip_network(line, strict=False)
    except ValueError:
        print(f"Invalid IP address or network: {line}", file=sys.stderr)
        return None


def subnet_sort_key(network):
    return (network.version, int(network.network_address), network.prefixlen)


def get_unique_subnets(input_file: str | Path):
    """Return a sorted list of unique subnets from the input file."""
    subnets = set()
    try:
        with Path(input_file).expanduser().open("r", encoding="utf-8") as handle:
            for line in handle:
                network = parse_ip_or_network(line)
                if network:
                    subnets.add(network)
    except OSError as exc:
        print(f"Error reading file '{input_file}': {exc}", file=sys.stderr)
        return None

    return sorted(subnets, key=subnet_sort_key)


def save_to_file(output_file: str | Path, subnets) -> bool:
    """Save the subnet list to a file."""
    try:
        with Path(output_file).expanduser().open("w", encoding="utf-8") as handle:
            for subnet in subnets:
                handle.write(f"{subnet}\n")
    except OSError as exc:
        print(f"Error writing to file '{output_file}': {exc}", file=sys.stderr)
        return False

    print(f"Unique subnets have been written to '{output_file}'")
    return True


def print_to_console(subnets) -> None:
    """Print the subnet list to the console."""
    print("Unique subnets:")
    for subnet in subnets:
        print(subnet)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        description="Get unique subnets from a list of IP addresses."
    )
    parser.add_argument("-i", "--input", help="Input file with list of IP addresses")
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

    unique_subnets = get_unique_subnets(args.input)
    if unique_subnets is None:
        return 1
    if not unique_subnets:
        print("No valid subnets were found.", file=sys.stderr)
        return 1

    if args.output:
        if not save_to_file(args.output, unique_subnets):
            return 1
    else:
        print_to_console(unique_subnets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
