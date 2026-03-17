#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import argparse
import logging
import re
import ipaddress
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def resolve_target(host):
    """Return domain if present in <host>, otherwise return IP."""
    ip = None
    domain = None

    # Extract IP address
    for address in host.findall('address'):
        addr = address.get('addr')
        if addr:
            ip = addr

    # Extract hostname
    for hostname in host.findall('./hostnames/hostname'):
        name = hostname.get('name')
        if name:
            domain = name

    return domain if domain else ip


_SCHEME_RE = re.compile(r'^\s*(?:https?://)', re.I)


def _normalize_host(raw: str) -> str:
    """
    Normalize a target value to a URL-ready host:
    - Strip scheme, path, userinfo, and optional port.
    - Preserve bare IPv6 literals (do not split by ':').
    - Wrap IPv6 host values in square brackets for URL formatting.
    - Trim trailing dot from FQDN.
    """
    if not raw:
        return raw

    s = raw.strip()
    host = None

    if _SCHEME_RE.match(s):
        host = urlsplit(s).hostname
    else:
        candidate = re.split(r"[/?#]", s, maxsplit=1)[0]
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[1]

        if candidate.startswith("["):
            closing = candidate.find("]")
            if closing != -1:
                host = candidate[1:closing]
            else:
                host = candidate.lstrip("[")
        else:
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                if candidate.count(":") == 1:
                    maybe_host, maybe_port = candidate.rsplit(":", 1)
                    if maybe_port.isdigit():
                        candidate = maybe_host
                host = urlsplit("//" + candidate).hostname or candidate
            else:
                host = candidate

    host = host or s

    # Remove trailing dot from FQDN (nmap may output it)
    if host.endswith('.'):
        host = host[:-1]

    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        return host.lower()

    if parsed_ip.version == 6:
        return f"[{host}]"
    return host


def _tokenize_service_name(service_name: str) -> list:
    """Split typical nmap service name by common delimiters."""
    s = (service_name or '').lower()
    return [t for t in re.split(r'[/|+:\-_.]', s) if t]


def _is_ssl_like(service_name: str, tunnel: str) -> bool:
    """Return True if service/tunnel clearly indicates SSL/TLS wrapping."""
    if (tunnel or '').lower() == 'ssl':
        return True

    s = (service_name or '').lower()
    if s in ('https', 'ssl', 'tls'):
        return True

    tokens = _tokenize_service_name(service_name)
    if 'ssl' in tokens or 'tls' in tokens:
        return True

    if s.startswith('ssl') or s.startswith('tls'):
        return True

    return False


def _is_httpish(service_name: str) -> bool:
    """
    Return True if the service looks HTTP-like:
    matches names like http, https, http-alt, http-proxy, ssl/http, http|ssl, etc.
    """
    s = (service_name or '').lower()
    if not s:
        return False
    if s in ('http', 'https'):
        return True
    tokens = _tokenize_service_name(s)
    return ('http' in tokens) or s.startswith('http') or ('http' in s)


def _format_url_host_port(host: str, portid: str, protocol: str) -> str:
    """Format URL with default port elided."""
    default_port = '443' if protocol == 'https' else '80'
    if portid == default_port:
        return f"{protocol}://{host}/"
    return f"{protocol}://{host}:{portid}/"


def build_url(target, port_element):
    """
    Build a URL from a <port> element if it is HTTP/HTTPS (including SSL-wrapped).
    """
    portid = port_element.get('portid')
    state_element = port_element.find('state')
    service_element = port_element.find('service')

    if state_element is None or state_element.get('state') != 'open':
        return None

    service = (service_element.get('name') if service_element is not None else '') or ''
    tunnel = (service_element.get('tunnel') if service_element is not None else '') or ''

    if not _is_httpish(service):
        return None

    protocol = 'https' if _is_ssl_like(service, tunnel) or service.lower() == 'https' else 'http'

    host = _normalize_host(target)
    return _format_url_host_port(host, portid, protocol)


def parse_nmap_xml(input_file: str | Path, output_file: str | Path) -> bool:
    """
    Parse nmap XML and extract URLs for HTTP/HTTPS services.
    Handles cases where the target name itself includes http(s)://.
    """
    input_path = Path(input_file).expanduser().resolve()
    output_path = Path(output_file).expanduser().resolve()

    if not input_path.is_file():
        raise FileNotFoundError(f"File {input_path} does not exist.")

    tree = ET.parse(input_path)

    root = tree.getroot()

    extracted_urls = []
    seen = set()  # de-duplicate exact URLs while preserving order

    for host in root.findall('host'):
        target = resolve_target(host)
        if not target:
            logging.debug("Failed to resolve target (IP or domain) for a host.")
            continue

        for port in host.findall('./ports/port'):
            url = build_url(target, port)
            if url and url not in seen:
                seen.add(url)
                extracted_urls.append(url)

    if not extracted_urls:
        logging.warning("No matching URLs were found.")
        return False

    with output_path.open('w', encoding='utf-8') as handle:
        for url in extracted_urls:
            handle.write(url + '\n')
    logging.info("URLs were written to %s", output_path)
    return True


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Extract HTTP/HTTPS URLs from nmap XML.')
    parser.add_argument('input_file', nargs='?', type=str, help='Input nmap XML file (legacy positional argument)')
    parser.add_argument('output_file', nargs='?', type=str, help='Output file to write URLs (legacy positional argument)')
    parser.add_argument('-i', '--input', dest='input_opt', type=str, help='Input nmap XML file')
    parser.add_argument('-o', '--output', dest='output_opt', type=str, help='Output file to write URLs')
    args = parser.parse_args(argv)

    resolved_input = args.input_opt or args.input_file
    resolved_output = args.output_opt or args.output_file
    if not resolved_input or not resolved_output:
        parser.error("Input and output are required (use positional args or -i/-o).")

    args.input_file = resolved_input
    args.output_file = resolved_output
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        parse_nmap_xml(args.input_file, args.output_file)
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
