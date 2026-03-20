#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path


MAX_EXPANDABLE_ADDRESSES_PER_PREFIX = 65536
MAX_EXPANDABLE_ADDRESSES_TOTAL = 262144


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def load_requests():
    try:
        import requests
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Missing dependency: install 'requests' to use get_ip_by_asn."
        ) from exc
    return requests


def normalize_asn(raw_value: str) -> str:
    value = raw_value.strip().upper()
    if value.startswith("AS"):
        value = value[2:]
    if not value.isdigit() or int(value) < 1:
        raise ValueError(f"Invalid ASN: {raw_value}")
    return value


def read_asns(input_file: str | Path) -> list[str] | None:
    input_path = Path(input_file).expanduser()
    try:
        with input_path.open("r", encoding="utf-8") as handle:
            values = []
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                values.append(normalize_asn(stripped))
            return values
    except OSError as exc:
        print(f"Error reading input file '{input_path}': {exc}", file=sys.stderr)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
    return None


def fetch_prefixes_for_asn(asn: str, requests_module=None) -> list[str]:
    requests_lib = load_requests() if requests_module is None else requests_module
    response = requests_lib.get(
        "https://stat.ripe.net/data/announced-prefixes/data.json",
        params={"resource": f"AS{asn}"},
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    prefixes = payload.get("data", {}).get("prefixes", [])
    return sorted(
        {
            entry["prefix"]
            for entry in prefixes
            if isinstance(entry, dict) and entry.get("prefix")
        }
    )


def sort_ip_strings(ips: list[str]) -> list[str]:
    return sorted(
        set(ips),
        key=lambda value: (
            ipaddress.ip_address(value).version,
            int(ipaddress.ip_address(value)),
        ),
    )


def expand_prefixes(
    prefixes: list[str],
    per_prefix_limit: int = MAX_EXPANDABLE_ADDRESSES_PER_PREFIX,
    total_limit: int = MAX_EXPANDABLE_ADDRESSES_TOTAL,
) -> tuple[list[str], list[str]]:
    addresses: list[str] = []
    skipped: list[str] = []

    for prefix in prefixes:
        network = ipaddress.ip_network(prefix, strict=False)
        if network.num_addresses > per_prefix_limit:
            skipped.append(prefix)
            continue
        if len(addresses) + network.num_addresses > total_limit:
            skipped.append(prefix)
            continue
        addresses.extend(str(ip) for ip in network)

    return sort_ip_strings(addresses), skipped


def write_results(addresses: list[str], output_file: str | Path | None = None) -> int:
    if not addresses:
        print("No IP addresses were collected for the requested ASN.", file=sys.stderr)
        return 1

    if output_file is None:
        for address in addresses:
            print(address)
        return 0

    output_path = Path(output_file).expanduser()
    try:
        with output_path.open("w", encoding="utf-8") as handle:
            for address in addresses:
                handle.write(address + "\n")
    except OSError as exc:
        print(f"Error writing to file '{output_path}': {exc}", file=sys.stderr)
        return 1

    print(f"Saved {len(addresses)} IP addresses to '{output_path.name}'")
    return 0


def process_asns(asns: list[str], output_file: str | Path | None = None) -> int:
    try:
        requests_module = load_requests()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    all_addresses: list[str] = []
    skipped_prefixes: list[str] = []

    for asn in asns:
        try:
            prefixes = fetch_prefixes_for_asn(asn, requests_module=requests_module)
        except Exception as exc:
            print(f"Error fetching prefixes for AS{asn}: {exc}", file=sys.stderr)
            continue

        addresses, skipped = expand_prefixes(prefixes)
        all_addresses.extend(addresses)
        skipped_prefixes.extend(skipped)

    unique_addresses = sort_ip_strings(all_addresses)
    result = write_results(unique_addresses, output_file)
    if skipped_prefixes:
        print(
            f"Warning: skipped {len(skipped_prefixes)} prefixes that exceeded expansion limits.",
            file=sys.stderr,
        )
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        description="Expand announced prefixes for one or more ASNs into individual IP addresses."
    )
    parser.add_argument("-a", "--asn", nargs="+", help="One or more ASN values, with or without the AS prefix.")
    parser.add_argument("-i", "--input", help="File containing ASN values, one per line.")
    parser.add_argument(
        "-o",
        "--output",
        help="Optional output file. If omitted, IP addresses are printed to stdout.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.asn and not args.input:
        print("Error: provide -a/--asn or -i/--input.", file=sys.stderr)
        return 1
    if args.asn and args.input:
        print("Error: use either -a/--asn or -i/--input, not both.", file=sys.stderr)
        return 1

    if args.asn:
        try:
            asns = [normalize_asn(value) for value in args.asn]
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
    else:
        asns = read_asns(args.input)
        if asns is None:
            return 1

    if not asns:
        print("No ASN values to process.", file=sys.stderr)
        return 1

    return process_asns(asns, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
