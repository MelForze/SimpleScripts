#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import argparse
import logging
import re
from pathlib import Path
from typing import Sequence

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def is_https_service(service_element):
    """Return True when nmap service metadata indicates HTTPS or SSL-wrapped HTTP."""
    if service_element is None:
        return False

    service_name = (service_element.get("name") or "").lower()
    tunnel = (service_element.get("tunnel") or "").lower()

    if service_name == "https" or tunnel == "ssl":
        return True

    tokens = [token for token in re.split(r"[/|+:\-_.]", service_name) if token]
    if "https" in tokens:
        return True

    if "http" in tokens and ("ssl" in tokens or "tls" in tokens):
        return True

    return False

def resolve_target(host):
    """
    Return the hostname if present; otherwise return an IP address.
    When selecting an IP, prefer addrtype in this order: ipv4, then ipv6.
    If neither ipv4 nor ipv6 is found, return any available addr.
    """
    ipv4_addrs = []
    ipv6_addrs = []
    other_addrs = []
    domain = None

    # Collect addresses by type
    for address in host.findall('address'):
        addr = address.get('addr')
        atype = (address.get('addrtype') or '').lower()
        if not addr:
            continue
        if atype == 'ipv4':
            ipv4_addrs.append(addr)
        elif atype == 'ipv6':
            ipv6_addrs.append(addr)
        else:
            other_addrs.append(addr)

    # Use hostname if available
    for hostname in host.findall('./hostnames/hostname'):
        name = hostname.get('name')
        if name:
            domain = name
            break

    if domain:
        return domain

    # Preference order: ipv4 -> ipv6 -> any other addr
    if ipv4_addrs:
        return ipv4_addrs[0]
    if ipv6_addrs:
        return ipv6_addrs[0]
    if other_addrs:
        return other_addrs[0]

    return None


def parse_nmap_xml(input_file: str | Path, output_file: str | Path, https_filter: bool) -> bool:
    input_path = Path(input_file).expanduser().resolve()
    output_path = Path(output_file).expanduser().resolve()

    if not input_path.is_file():
        raise FileNotFoundError(f"File {input_path} does not exist.")

    tree = ET.parse(input_path)
    root = tree.getroot()

    lines_to_write = []

    for host in root.findall('host'):
        target = resolve_target(host)
        if not target:
            logging.debug("Failed to determine domain or IP for a host.")
            continue

        open_ports = set()
        for port in host.findall('./ports/port'):
            state_element = port.find('state')
            if state_element is None or state_element.get('state') != 'open':
                continue

            if https_filter:
                service = port.find('service')
                if not is_https_service(service):
                    continue

            portid = port.get('portid')
            if not portid:
                continue
            try:
                port_num = int(portid)
            except ValueError:
                logging.debug("Skipping non-numeric port identifier: %r", portid)
                continue
            if not (1 <= port_num <= 65535):
                logging.debug("Skipping out-of-range port: %s", port_num)
                continue
            open_ports.add(port_num)

        if open_ports:
            ports_str = ', '.join(str(port) for port in sorted(open_ports))
            line = f"{target} [{ports_str}]"
            lines_to_write.append(line)

    if not lines_to_write:
        logging.warning("No open ports or targets found for output.")
        return False

    with output_path.open('w', encoding='utf-8') as handle:
        for line in lines_to_write:
            handle.write(line + '\n')
    logging.info("Output written to %s", output_path)
    return True


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Nmap XML parser to extract domain/IP and open ports.')
    parser.add_argument('-i', '--input', required=True, type=str, help='Input XML file')
    parser.add_argument('-o', '--output', required=True, type=str, help='Output file')
    parser.add_argument('--https', action='store_true', help='Output only ports with https service')
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        parse_nmap_xml(args.input, args.output, args.https)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        return 1
    except ET.ParseError as exc:
        logging.error("Failed to parse XML: %s", exc)
        return 1
    except OSError as exc:
        logging.error("I/O error: %s", exc)
        return 1

    return 0

if __name__ == '__main__':
    raise SystemExit(main())
