#!/usr/bin/env python3
"""Extract IP addresses for nmap hosts with at least one open port."""

import argparse
import ipaddress
import logging
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def host_is_up(host: ET.Element) -> bool:
    """Return True when the host is up or when status is absent."""
    status = host.find("status")
    if status is None:
        return True
    return (status.get("state") or "").lower() == "up"


def host_has_open_port(host: ET.Element) -> bool:
    """Return True when any port on the host has state=open."""
    for port in host.findall('./ports/port'):
        state_element = port.find('state')
        if state_element is not None and state_element.get('state') == 'open':
            return True
    return False


def host_ip_addresses(host: ET.Element) -> list[str]:
    """Return valid IPv4/IPv6 addresses from an nmap host element."""
    addresses: list[str] = []

    for address in host.findall('address'):
        addr = address.get('addr')
        if not addr:
            continue

        try:
            ipaddress.ip_address(addr)
        except ValueError:
            logging.debug("Skipping non-IP address: %r", addr)
            continue

        addresses.append(addr)

    return addresses


def write_lines(lines: list[str], output_path: Path | None) -> None:
    output_text = "".join(f"{line}\n" for line in lines)
    if output_path is None:
        sys.stdout.write(output_text)
        return

    with output_path.open('w', encoding='utf-8') as handle:
        handle.write(output_text)
    logging.info("Output written to %s", output_path)


def parse_nmap_xml(
    input_file: str | Path,
    output_file: str | Path | None = None,
) -> bool:
    """Parse nmap XML and output IPs for hosts with at least one open port."""
    input_path = Path(input_file).expanduser().resolve()
    output_path = Path(output_file).expanduser().resolve() if output_file else None

    if not input_path.is_file():
        raise FileNotFoundError(f"File {input_path} does not exist.")

    tree = ET.parse(input_path)
    root = tree.getroot()

    ips: list[str] = []
    seen: set[str] = set()

    for host in root.findall('host'):
        if not host_is_up(host):
            logging.debug("Skipping host because its state is not up.")
            continue

        if not host_has_open_port(host):
            continue

        for ip in host_ip_addresses(host):
            if ip in seen:
                continue
            seen.add(ip)
            ips.append(ip)

    if not ips:
        logging.warning("No IP addresses with open ports were found.")
        return False

    write_lines(ips, output_path)
    return True


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        description='Extract IP addresses from nmap XML hosts with at least one open port.'
    )
    parser.add_argument('-i', '--input', required=True, type=str, help='Input nmap XML file')
    parser.add_argument('-o', '--output', type=str, help='Output file (default: stdout)')
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        wrote_output = parse_nmap_xml(args.input, args.output)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        return 1
    except ET.ParseError as exc:
        logging.error("Failed to parse XML: %s", exc)
        return 1
    except OSError as exc:
        logging.error("I/O error: %s", exc)
        return 1

    if not wrote_output:
        return 2

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
