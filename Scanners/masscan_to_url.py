#!/usr/bin/env python3
"""
Convert masscan output to a list of HTTP/HTTPS URLs only.

Supported input formats:
- Standard masscan text output, e.g.:
    Discovered open port 80/tcp on 192.168.0.1

- List output (-oL), e.g.:
    open tcp 80 93.184.216.34 1497471453
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Regex for "Discovered" style lines
RE_DISCOVERED = re.compile(
    r"Discovered open port (\d+)/(\w+) on ([0-9a-fA-F\.:]+)"
)

# Regex for list-output (-oL) lines
RE_LIST = re.compile(
    r"^open\s+(\w+)\s+(\d+)\s+([0-9a-fA-F\.:]+)"
)

# Ports typically used for HTTP/HTTPS services
HTTP_PORTS = {
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

# Mapping from scheme to its "default" port
SCHEME_DEFAULT_PORT: Dict[str, int] = {
    "http": 80,
    "https": 443,
}


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = create_argument_parser(
        description="Convert masscan output to a list of HTTP/HTTPS URLs."
    )
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        help="Input file with masscan output (default: stdin).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file for URLs (default: stdout).",
    )
    parser.add_argument(
        "-ap",
        "--all-ports",
        action="store_true",
        help="Generate HTTP and HTTPS URLs for every open TCP port.",
    )
    return parser.parse_args(argv)


def read_lines(path: Path | None) -> Iterable[str]:
    """
    Yield lines from a file or stdin.

    :param path: Path to input file, or None to read from stdin.
    """
    if path is None:
        for line in sys.stdin:
            yield line.rstrip("\n")
    else:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line.rstrip("\n")


def extract_hosts_ports(line: str) -> List[Tuple[str, int]]:
    """
    Extract (host, port) pairs from a single line of masscan output.

    This function tries multiple known masscan output formats.
    Returns an empty list if no hosts/ports are found.
    """
    results: List[Tuple[str, int]] = []

    # Match "Discovered open port ..." style
    m = RE_DISCOVERED.search(line)
    if m:
        protocol = m.group(2).lower()
        if protocol != "tcp":
            return results
        port = int(m.group(1))
        host = m.group(3)
        results.append((host, port))

    # Match list-output "open tcp 80 1.2.3.4" style
    m = RE_LIST.search(line)
    if m:
        protocol = m.group(1).lower()
        if protocol != "tcp":
            return results
        port = int(m.group(2))
        host = m.group(3)
        results.append((host, port))

    return results


def normalize_host_for_url(host: str) -> str:
    """
    Normalize host for URL.

    - Wrap IPv6 addresses in square brackets, as required by URL syntax.
    """
    # A simple heuristic: IPv6 addresses contain ':' and are not already wrapped.
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host


def port_to_web_scheme(port: int) -> str | None:
    """
    Return HTTP/HTTPS scheme for a given port.

    If the port is not recognized as a web port, return None.
    """
    return HTTP_PORTS.get(port)


def make_url(
    host: str,
    port: int,
) -> str | None:
    """
    Build an HTTP/HTTPS URL from host and port.

    Returns None if the port is not a known HTTP/HTTPS port.
    """
    scheme = port_to_web_scheme(port)
    if scheme is None:
        # Not a web port -> skip
        return None

    normalized_host = normalize_host_for_url(host)
    default_port = SCHEME_DEFAULT_PORT.get(scheme)

    # Decide whether to include port in the URL
    if default_port is not None and port == default_port:
        return f"{scheme}://{normalized_host}"
    return f"{scheme}://{normalized_host}:{port}"


def make_all_port_urls(host: str, port: int) -> List[str]:
    """Build HTTP and HTTPS URLs for any open TCP port."""
    normalized_host = normalize_host_for_url(host)
    return [
        f"http://{normalized_host}:{port}",
        f"https://{normalized_host}:{port}",
    ]


def masscan_to_urls(
    lines: Iterable[str],
    all_ports: bool = False,
) -> List[str]:
    """
    Convert an iterable of masscan output lines to a list of unique HTTP/HTTPS URLs.

    By default only ports recognized as HTTP/HTTPS are converted.
    URLs are deduplicated while preserving the first-seen order.
    """
    seen: Set[str] = set()
    urls: List[str] = []

    for line in lines:
        # Skip obvious comment / header lines
        if line.startswith("#") or not line.strip():
            continue

        for host, port in extract_hosts_ports(line):
            generated_urls = (
                make_all_port_urls(host, port)
                if all_ports
                else [make_url(host=host, port=port)]
            )
            for generated_url in generated_urls:
                if generated_url is None:
                    # Non-web port, skip it
                    continue
                if generated_url not in seen:
                    seen.add(generated_url)
                    urls.append(generated_url)

    return urls


def write_urls(urls: Iterable[str], path: Path | None) -> None:
    """
    Write URLs either to a file or stdout.

    :param urls: Iterable of URLs as strings.
    :param path: Path to output file, or None to write to stdout.
    """
    output_text = "\n".join(urls) + ("\n" if urls else "")

    if path is None:
        sys.stdout.write(output_text)
    else:
        path.write_text(output_text, encoding="utf-8")


def main(argv: List[str] | None = None) -> int:
    """Main entry point."""
    args = parse_args(argv)
    if args.input is not None and not args.input.is_file():
        logging.error("Input file does not exist: %s", args.input)
        return 1

    try:
        lines = read_lines(args.input)
        urls = masscan_to_urls(lines=lines, all_ports=args.all_ports)
        if not urls:
            logging.warning("No matching HTTP/HTTPS URLs were found.")
            return 2
        write_urls(urls, args.output)
    except OSError as exc:
        logging.error("I/O error: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
