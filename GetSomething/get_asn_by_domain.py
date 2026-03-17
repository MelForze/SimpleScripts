#!/usr/bin/env python3

import argparse
import socket
import sys
from ipwhois import IPWhois


def get_asn(domain: str):
    """Retrieve ASN for a single domain name."""
    try:
        ip_address = socket.gethostbyname(domain)
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        return result.get("asn")
    except (socket.gaierror, OSError) as exc:
        print(f"Error fetching ASN for {domain}: {exc}", file=sys.stderr)
        return None


def process_domains(domains: list[str], output_file: str | None = None) -> int:
    """Process a domain list and output ASN results."""
    results = []
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        asn = get_asn(domain)
        if asn is not None:
            result = f"For domain {domain} ASN: {asn}"
            results.append(result)
            if output_file is None:
                print(result)

    if output_file is not None:
        try:
            with open(output_file, "w", encoding="utf-8") as f_out:
                for result in results:
                    f_out.write(result + "\n")
        except OSError as exc:
            print(f"Error writing output file '{output_file}': {exc}", file=sys.stderr)
            return 1
    return 0


def main(input_file: str | None = None, output_file: str | None = None, domain_list=None) -> int:
    """Main entry point for domain processing."""
    domains: list[str] = []

    if domain_list:
        domains = domain_list
    elif input_file:
        try:
            with open(input_file, "r", encoding="utf-8") as f:
                domains = [line.strip() for line in f.readlines()]
        except OSError as exc:
            print(f"Error reading input file '{input_file}': {exc}", file=sys.stderr)
            return 1

    domains = [domain for domain in domains if domain]
    if not domains:
        print("No domains to process.", file=sys.stderr)
        return 1

    return process_domains(domains, output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrieves ASN for a list of domains.")
    parser.add_argument("-i", "--input", help="File with domains.")
    parser.add_argument(
        "-o",
        "--output",
        help="File to write results. If not specified, the console is used.",
    )
    parser.add_argument("-d", "--domains", nargs="+", help="One or more domains to process.")

    args = parser.parse_args()

    if not args.input and not args.domains:
        parser.print_help()
        raise SystemExit(1)

    raise SystemExit(main(args.input, args.output, args.domains))
