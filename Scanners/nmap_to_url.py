#!/usr/bin/env python3
"""Extract HTTP/HTTPS URLs from nmap XML output."""

import argparse
import ipaddress
import logging
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

WEB_PORT_SCHEMES = {
    80: "http",
    443: "https",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8443: "https",
    8888: "http",
    9000: "http",
    9443: "https",
}


def resolve_targets(host: ET.Element, all_hostnames: bool = False) -> list[str]:
    """
    Return one or more targets for a host.

    Prefer hostname(s) when present; otherwise return an IP address.
    When selecting an IP, prefer addrtype in this order: ipv4, then ipv6.
    If neither ipv4 nor ipv6 is found, return any available addr.
    """
    ipv4_addrs = []
    ipv6_addrs = []
    other_addrs = []
    hostnames = []

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

    for hostname in host.findall('./hostnames/hostname'):
        name = hostname.get('name')
        if name:
            hostnames.append(name)

    if hostnames:
        if all_hostnames:
            return hostnames
        return [hostnames[0]]

    if ipv4_addrs:
        return [ipv4_addrs[0]]
    if ipv6_addrs:
        return [ipv6_addrs[0]]
    if other_addrs:
        return [other_addrs[0]]
    return []


def resolve_target(host: ET.Element) -> str | None:
    """Backward-compatible single-target resolver."""
    targets = resolve_targets(host)
    if not targets:
        return None
    return targets[0]


def host_is_up(host: ET.Element) -> bool:
    """Return True when the host is up or when status is absent."""
    status = host.find("status")
    if status is None:
        return True
    return (status.get("state") or "").lower() == "up"


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


def _guess_scheme_by_port(portid: str | None) -> str | None:
    """Return a guessed HTTP/HTTPS scheme for common web ports."""
    if not portid:
        return None
    try:
        port_num = int(portid)
    except ValueError:
        return None
    return WEB_PORT_SCHEMES.get(port_num)


def build_url(target: str, port_element: ET.Element) -> str | None:
    """
    Build a URL from a <port> element if it is HTTP/HTTPS (including SSL-wrapped).
    """
    portid = port_element.get('portid')
    protocol_attr = (port_element.get('protocol') or '').lower()
    state_element = port_element.find('state')
    service_element = port_element.find('service')

    if protocol_attr != 'tcp':
        return None

    if state_element is None or state_element.get('state') != 'open':
        return None

    service = (service_element.get('name') if service_element is not None else '') or ''
    tunnel = (service_element.get('tunnel') if service_element is not None else '') or ''
    guessed_protocol = _guess_scheme_by_port(portid)

    if _is_httpish(service):
        protocol = 'https' if _is_ssl_like(service, tunnel) or service.lower() == 'https' else 'http'
    elif guessed_protocol is not None:
        protocol = guessed_protocol
    else:
        return None

    host = _normalize_host(target)
    return _format_url_host_port(host, portid, protocol)


def build_all_port_urls(target: str, port_element: ET.Element) -> list[str]:
    """
    Build HTTP and HTTPS URLs for any open TCP <port> element.
    """
    portid = port_element.get('portid')
    protocol_attr = (port_element.get('protocol') or '').lower()
    state_element = port_element.find('state')

    if protocol_attr != 'tcp':
        return []

    if state_element is None or state_element.get('state') != 'open':
        return []

    if not portid:
        return []

    host = _normalize_host(target)
    return [
        f"http://{host}:{portid}/",
        f"https://{host}:{portid}/",
    ]


def _all_port_url_sort_key(url: str) -> tuple[str, int, int, str]:
    """Sort all-ports URLs by host, numeric port, then scheme."""
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        port = None

    scheme_order = {"http": 0, "https": 1}.get(parsed.scheme, 2)
    return (parsed.hostname or "", port or 0, scheme_order, url)


def _write_urls(extracted_urls: list[str], output_path: Path | None) -> None:
    output_text = "".join(f"{url}\n" for url in extracted_urls)
    if output_path is None:
        sys.stdout.write(output_text)
        return

    with output_path.open('w', encoding='utf-8') as handle:
        handle.write(output_text)
    logging.info("URLs were written to %s", output_path)


def parse_nmap_xml(
    input_file: str | Path,
    output_file: str | Path | None,
    all_hostnames: bool = False,
    all_ports: bool = False,
) -> bool:
    """
    Parse nmap XML and extract URLs for HTTP/HTTPS services.
    Handles cases where the target name itself includes http(s)://.
    """
    input_path = Path(input_file).expanduser().resolve()
    output_path = Path(output_file).expanduser().resolve() if output_file else None

    if not input_path.is_file():
        raise FileNotFoundError(f"File {input_path} does not exist.")

    tree = ET.parse(input_path)

    root = tree.getroot()

    extracted_urls = []
    seen = set()  # de-duplicate exact URLs while preserving order

    for host in root.findall('host'):
        if not host_is_up(host):
            logging.debug("Skipping host because its state is not up.")
            continue

        targets = resolve_targets(host, all_hostnames=all_hostnames)
        if not targets:
            logging.debug("Failed to resolve target (IP or domain) for a host.")
            continue

        for port in host.findall('./ports/port'):
            for target in targets:
                urls = (
                    build_all_port_urls(target, port)
                    if all_ports
                    else [build_url(target, port)]
                )
                for url in urls:
                    if url and url not in seen:
                        seen.add(url)
                        extracted_urls.append(url)

    if not extracted_urls:
        logging.warning("No matching URLs were found.")
        return False

    if all_ports:
        extracted_urls.sort(key=_all_port_url_sort_key)
    else:
        extracted_urls.sort()
    _write_urls(extracted_urls, output_path)
    return True


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(description='Extract HTTP/HTTPS URLs from nmap XML.')
    parser.add_argument('-i', '--input', required=True, type=str, help='Input nmap XML file')
    parser.add_argument(
        '-o',
        '--output',
        type=str,
        help='Output file to write URLs (default: stdout)',
    )
    parser.add_argument(
        '-ah',
        '--all-hostnames',
        action='store_true',
        help='Generate URLs for every hostname in a host entry instead of only the first one.',
    )
    parser.add_argument(
        '-ap',
        '--all-ports',
        action='store_true',
        dest='all_ports',
        help='Generate HTTP and HTTPS URLs for every open TCP port.',
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        wrote_output = parse_nmap_xml(
            args.input,
            args.output,
            all_hostnames=args.all_hostnames,
            all_ports=args.all_ports,
        )
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
