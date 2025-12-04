#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import argparse
import os
import sys
import logging
import re
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
    Normalize a host value:
    - Strip scheme (http/https), path, userinfo, and port.
    - Keep only the hostname.
    - Wrap bare IPv6 literals in [] for use inside URLs.
    - Trim trailing dot from FQDN.
    Works for inputs like: "https://host:8080", "host:8080", "host/",
    "2001:db8::1", "[2001:db8::1]:443", etc.
    """
    if not raw:
        return raw

    s = raw.strip()

    # Use urlsplit to parse hostname. For "host:port" without scheme,
    # prefix with "//" so hostname/port are parsed as netloc.
    # See Python docs and common recipes for parsing host:port with urlsplit.
    # https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlsplit
    # https://stackoverflow.com/a/53188245
    if _SCHEME_RE.match(s):
        parts = urlsplit(s)
    else:
        parts = urlsplit('//' + s)

    host = parts.hostname or s

    # Remove trailing dot from FQDN (nmap may output it)
    if host.endswith('.'):
        host = host[:-1]

    # If it's an IPv6 literal (hostname will not include the port here),
    # wrap it in square brackets to form a valid URL host.
    # RFC 3986 requires brackets for IPv6 in URLs.
    # https://datatracker.ietf.org/doc/html/rfc3986
    if ':' in host and not host.startswith('[') and not host.endswith(']'):
        host = f'[{host}]'

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


def parse_nmap_xml(input_file, output_file):
    """
    Parse nmap XML and extract URLs for HTTP/HTTPS services.
    Handles cases where the target name itself includes http(s)://.
    """
    input_file = os.path.abspath(input_file)
    output_file = os.path.abspath(output_file)

    if not os.path.isfile(input_file):
        logging.error(f"File {input_file} does not exist.")
        sys.exit(1)

    try:
        tree = ET.parse(input_file)
    except ET.ParseError as e:
        logging.error(f"Failed to parse XML: {e}")
        sys.exit(1)

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
    else:
        with open(output_file, 'w', encoding='utf-8') as f:
            for url in extracted_urls:
                f.write(url + '\n')
        logging.info(f"URLs were written to {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Extract HTTP/HTTPS URLs from nmap XML.')
    parser.add_argument('input_file', type=str, help='Input nmap XML file')
    parser.add_argument('output_file', type=str, help='Output file to write URLs')
    args = parser.parse_args()
    parse_nmap_xml(args.input_file, args.output_file)


if __name__ == '__main__':
    main()