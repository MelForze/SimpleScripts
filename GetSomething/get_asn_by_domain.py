#!/usr/bin/env python3

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def load_ipwhois():
    try:
        from ipwhois import IPWhois
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Missing dependency: install 'ipwhois' to use get_asn_by_domain."
        ) from exc
    return IPWhois


def lookup_asn_with_cymru(
    ip_address: str,
    connection_factory=socket.create_connection,
) -> str | None:
    """
    Query Team Cymru whois as a dependency-free ASN fallback.
    """
    query = f"begin\nverbose\n{ip_address}\nend\n".encode("ascii")
    response = bytearray()

    with connection_factory(("whois.cymru.com", 43), timeout=5) as connection:
        connection.sendall(query)
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)

    text = response.decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("AS") or stripped.startswith("Bulk mode"):
            continue
        parts = [part.strip() for part in stripped.split("|")]
        if not parts:
            continue
        asn = parts[0]
        if asn and asn.upper() != "NA":
            return asn
    return None


def get_asn(domain: str, ipwhois_cls=None) -> str | None:
    """Retrieve ASN for a single domain name."""
    try:
        ip_address = socket.gethostbyname(domain)
    except (socket.gaierror, OSError) as exc:
        print(f"Error fetching ASN for {domain}: {exc}", file=sys.stderr)
        return None

    whois_class = ipwhois_cls
    if whois_class is None:
        try:
            whois_class = load_ipwhois()
        except RuntimeError:
            whois_class = None

    if whois_class is not None:
        try:
            result = whois_class(ip_address).lookup_rdap()
            asn = result.get("asn")
            if asn:
                return asn
        except OSError as exc:
            print(f"Warning: ipwhois lookup failed for {domain}: {exc}", file=sys.stderr)

    try:
        asn = lookup_asn_with_cymru(ip_address)
    except OSError as exc:
        print(f"Error fetching ASN for {domain}: {exc}", file=sys.stderr)
        return None

    if asn:
        return asn

    print(f"Error fetching ASN for {domain}: ASN lookup returned no result.", file=sys.stderr)
    return None


def read_domains(input_file: Path) -> list[str] | None:
    try:
        with input_file.expanduser().open("r", encoding="utf-8") as handle:
            return [
                line.strip()
                for line in handle
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except OSError as exc:
        print(f"Error reading input file '{input_file}': {exc}", file=sys.stderr)
        return None


def process_domains(domains: list[str], output_file: Path | None = None) -> int:
    """Process a domain list and output ASN results."""
    if not domains:
        print("No domains to process.", file=sys.stderr)
        return 1

    try:
        ipwhois_cls = load_ipwhois()
    except RuntimeError:
        ipwhois_cls = None

    results: list[str] = []
    for domain in domains:
        asn = get_asn(domain, ipwhois_cls=ipwhois_cls)
        if asn is None:
            continue
        result = f"For domain {domain} ASN: {asn}"
        results.append(result)
        if output_file is None:
            print(result)

    if not results:
        print("No ASN results were found.", file=sys.stderr)
        return 1

    if output_file is not None:
        try:
            with output_file.expanduser().open("w", encoding="utf-8") as handle:
                for result in results:
                    handle.write(result + "\n")
        except OSError as exc:
            print(f"Error writing output file '{output_file}': {exc}", file=sys.stderr)
            return 1

    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(description="Retrieve ASN values for one or more domains.")
    parser.add_argument("-i", "--input", help="File containing domains, one per line.")
    parser.add_argument(
        "-o",
        "--output",
        help="Optional file to write results. If omitted, results are printed to stdout.",
    )
    parser.add_argument("-d", "--domains", nargs="+", help="One or more domains to process.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if not args.input and not args.domains:
        print("Error: provide -i/--input or -d/--domains.", file=sys.stderr)
        return 1
    if args.input and args.domains:
        print("Error: use either -i/--input or -d/--domains, not both.", file=sys.stderr)
        return 1

    if args.domains:
        domains = [domain.strip() for domain in args.domains if domain.strip()]
        if not domains:
            print("No domains to process.", file=sys.stderr)
            return 1
    else:
        loaded_domains = read_domains(Path(args.input))
        if loaded_domains is None:
            return 1
        if not loaded_domains:
            print("No domains to process.", file=sys.stderr)
            return 1
        domains = loaded_domains

    output_path = Path(args.output) if args.output else None
    return process_domains(domains, output_path)


if __name__ == "__main__":
    raise SystemExit(main())
