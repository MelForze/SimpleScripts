#!/usr/bin/env python3
"""
Extract and normalize unique domain names from a text file.

- Scans the file content and finds domains using a regular expression.
- Normalizes domains:
    * lowercases
    * trims surrounding whitespace
    * removes trailing dots: example.com. -> example.com
    * strips leading 'www.': www.example.com -> example.com
- Writes the result either to a file or to stdout.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, Set


# Regular expression used to find domain-like strings in the input text.
DOMAIN_REGEX = re.compile(
    r'\b(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,}\b'
)


def normalize_domain(domain: str) -> str | None:
    """
    Normalize a domain string.

    Rules:
    - strip surrounding whitespace
    - convert to lowercase
    - remove one or more trailing dots
    - remove leading 'www.' (after lowercasing)

    Returns:
        Normalized domain, or None if it becomes empty.
    """
    d = domain.strip().lower()
    if not d:
        return None

    # Remove one or more trailing dots.
    while d.endswith("."):
        d = d[:-1]

    # Strip leading 'www.' if present.
    if d.startswith("www."):
        d = d[4:]

    return d or None


def find_domains(file_path: Path) -> Set[str]:
    """
    Find and return a set of unique, normalized domains from a file.

    The entire file content is scanned with a regex, and each match is normalized.
    """
    unique_domains: Set[str] = set()
    try:
        file_path = file_path.expanduser().resolve()
        with file_path.open("r", encoding="utf-8") as file:
            content = file.read()
    except FileNotFoundError:
        print(f"Error: Input file '{file_path.name}' not found.", file=sys.stderr)
        return unique_domains
    except OSError as e:
        print(f"Error reading file '{file_path.name}': {e}", file=sys.stderr)
        return unique_domains

    if not content.strip():
        print(f"Warning: Input file '{file_path.name}' is empty.", file=sys.stderr)
        return unique_domains

    domains = DOMAIN_REGEX.findall(content)
    if not domains:
        print(
            f"No domain names found in the input file '{file_path.name}'.",
            file=sys.stderr,
        )
        return unique_domains

    for domain in domains:
        normalized = normalize_domain(domain)
        if normalized:
            unique_domains.add(normalized)

    return unique_domains


def confirm_overwrite(path: Path) -> bool:
    """
    Ask the user whether to overwrite an existing non-empty file.

    Returns:
        True if the user confirms overwrite, False otherwise.
    """
    while True:
        answer = input(
            f"Output file '{path.name}' already exists and is not empty. "
            "Overwrite? [y/N]: "
        ).strip().lower()

        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no", ""):
            return False
        print("Please answer 'y' or 'n'.")


def write_to_file(domains: Iterable[str], output_file: Path) -> None:
    """
    Write unique domains to the specified output file, one per line.

    If the file already exists and is not empty, the user will be asked
    to confirm overwriting it.
    """
    output_file = output_file.expanduser().resolve()

    # Ensure the output directory exists.
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        # Only print the file name in the message.
        print(
            f"Error creating directory for output file '{output_file.name}': {e}",
            file=sys.stderr,
        )
        return

    # If file exists and is not empty, ask for confirmation.
    if output_file.exists():
        try:
            if output_file.stat().st_size > 0:
                if not confirm_overwrite(output_file):
                    print("Aborted: output file will not be overwritten.")
                    return
        except OSError as e:
            print(
                f"Error checking output file '{output_file.name}': {e}",
                file=sys.stderr,
            )
            return

    try:
        with output_file.open("w", encoding="utf-8") as file:
            for domain in sorted(domains):
                file.write(domain + "\n")
        print(f"Unique domain names have been written to '{output_file.name}'")
    except OSError as e:
        print(f"Error writing to file '{output_file.name}': {e}", file=sys.stderr)


def output_to_console(domains: Iterable[str]) -> None:
    """
    Print unique domains to stdout.

    If there are no domains, a message is written to stderr instead.
    """
    domains = sorted(domains)
    if not domains:
        print("No unique domains found to output.", file=sys.stderr)
        return

    print("Unique domain names:")
    for domain in domains:
        print(domain)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Extract unique domain names from a file and optionally write "
            "them to an output file."
        )
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input file path containing domain data.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Output file path to save unique domain names. "
            "If not specified, results are printed to the console."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """
    Entry point: parse arguments and run the extraction.
    """
    args = parse_args(argv)

    input_path = Path(args.input)
    unique_domains = find_domains(input_path)

    if not unique_domains:
        # All relevant messages already printed inside find_domains / output functions.
        return 0

    if args.output:
        output_path = Path(args.output)
        write_to_file(unique_domains, output_path)
    else:
        output_to_console(unique_domains)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())