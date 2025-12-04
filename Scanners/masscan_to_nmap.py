#!/usr/bin/env python3
"""
Script to extract unique open TCP ports from an input file
and generate two nmap scan commands: Fast TCP Scan and Full TCP Scan.
"""

import os
import argparse
import logging
from typing import Set

def setup_logging(verbose: bool) -> None:
    """Configure logging: DEBUG if verbose, otherwise INFO."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logging.debug("Logger initialized.")

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract unique open TCP ports and generate two nmap commands."
    )
    parser.add_argument(
        'file',
        metavar='FILE',
        help="Path to the input scan file"
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose logging"
    )
    return parser.parse_args()

def extract_ports(file_path: str) -> Set[int]:
    """
    Read the file, look for lines starting with 'open tcp',
    convert port values to int, collect unique ports.
    """
    ports: Set[int] = set()
    with open(file_path, 'r') as f:
        for line in f:
            if line.startswith("open tcp"):
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        port = int(parts[2])
                        ports.add(port)
                        logging.debug(f"Found open port: {port}")
                    except ValueError:
                        logging.warning(f"Skipping invalid port: {parts[2]!r}")
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

def main():
    args = parse_args()
    setup_logging(args.verbose)

    file_path = os.path.abspath(args.file)
    if not os.path.isfile(file_path):
        logging.error(f"File not found: {file_path}")
        exit(1)

    ports = extract_ports(file_path)
    if not ports:
        logging.info("No open ports found.")
        return

    fast_cmd, full_cmd = generate_commands(ports)
    logging.info("Generated commands:")
    print("\n[+] Fast TCP Scan\n")
    print(fast_cmd)
    print("\n[+] Full TCP Scan\n")
    print(full_cmd)

if __name__ == "__main__":
    main()