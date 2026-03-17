#!/usr/bin/env python3
"""
Script to extract unique open TCP ports from an input file
and generate two nmap scan commands: Fast TCP Scan and Full TCP Scan.
"""

import argparse
import logging
import re
from pathlib import Path
from typing import Iterable
from typing import Set
from typing import Sequence


logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

RE_DISCOVERED_TCP = re.compile(r"Discovered open port (\d+)/tcp on ", re.IGNORECASE)
RE_LIST_TCP = re.compile(r"^open\s+tcp\s+(\d+)\s+", re.IGNORECASE)


def setup_logging(verbose: bool) -> None:
    """Configure logging: DEBUG if verbose, otherwise INFO."""
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract unique open TCP ports and generate two nmap commands."
    )
    parser.add_argument(
        'file',
        nargs='?',
        metavar='FILE',
        help="Path to the input scan file (legacy positional argument)"
    )
    parser.add_argument(
        '-i', '--input',
        dest='input_file',
        help="Path to the input scan file"
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose logging"
    )
    args = parser.parse_args(argv)
    resolved_input = args.input_file or args.file
    if not resolved_input:
        parser.error("Input file is required (use FILE or -i/--input).")
    args.file = resolved_input
    return args


def _extract_port_from_line(line: str) -> int | None:
    discovered_match = RE_DISCOVERED_TCP.search(line)
    if discovered_match:
        return int(discovered_match.group(1))

    list_match = RE_LIST_TCP.search(line)
    if list_match:
        return int(list_match.group(1))

    return None


def _iter_lines(file_path: Path) -> Iterable[str]:
    with file_path.open('r', encoding='utf-8', errors='ignore') as handle:
        for line in handle:
            yield line.rstrip('\n')


def extract_ports(file_path: str | Path) -> Set[int]:
    """
    Read the file and collect unique TCP ports from known masscan output formats.
    """
    path = Path(file_path)
    ports: Set[int] = set()

    for line in _iter_lines(path):
        if not line or line.startswith("#"):
            continue

        try:
            port = _extract_port_from_line(line)
        except ValueError:
            logging.warning("Skipping invalid line: %r", line)
            continue

        if port is None:
            continue
        if not (1 <= port <= 65535):
            logging.warning("Skipping out-of-range port: %s", port)
            continue

        ports.add(port)
        logging.debug("Found open port: %s", port)

    return ports


def generate_commands(ports: Set[int]) -> tuple[str, str]:
    """Generate Fast and Full TCP scan commands with sorted port list."""
    sorted_ports = sorted(ports)
    ports_str = ",".join(map(str, sorted_ports))

    fast = (
        "sudo nmap -Pn -n -sS -sV --version-all --open "
        f"-p {ports_str} --min-rate 1999 --max-rate 2000 --max-retries 1 "
        "--min-rtt-timeout 50ms --max-rtt-timeout 150ms "
        "-v -oA nmap/scope_tcp_fast -iL domains.txt"
    )
    full = (
        "sudo nmap -Pn -n -sS -sV -sC --version-all --open "
        f"-p {ports_str} --min-rate 999 --max-rate 1000 --max-retries 1 "
        "--min-rtt-timeout 50ms --max-rtt-timeout 150ms "
        "-v -oA nmap/scope_full -iL domains.txt"
    )
    return fast, full


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    file_path = Path(args.file).expanduser().resolve()
    if not file_path.is_file():
        logging.error("File not found: %s", file_path)
        return 1

    try:
        ports = extract_ports(file_path)
    except OSError as exc:
        logging.error("I/O error while reading %s: %s", file_path, exc)
        return 1

    if not ports:
        logging.warning("No open TCP ports found.")
        return 0

    fast_cmd, full_cmd = generate_commands(ports)
    logging.info("Generated commands.")
    print("\n[+] Fast TCP Scan\n")
    print(fast_cmd)
    print("\n[+] Full TCP Scan\n")
    print(full_cmd)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
