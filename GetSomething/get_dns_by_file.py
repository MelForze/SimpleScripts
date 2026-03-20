#!/usr/bin/env python3
"""
Extract and normalize unique domain names from a text file.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)


def normalize_domain(domain: str) -> str | None:
    d = domain.strip().lower()
    if not d:
        return None

    while d.endswith("."):
        d = d[:-1]

    if d.startswith("www."):
        d = d[4:]

    return d or None


def find_domains(file_path: Path) -> set[str]:
    unique_domains: set[str] = set()
    try:
        resolved_path = file_path.expanduser().resolve()
        with resolved_path.open("r", encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        print(f"Error: Input file '{file_path.name}' not found.", file=sys.stderr)
        return unique_domains
    except OSError as exc:
        print(f"Error reading file '{file_path.name}': {exc}", file=sys.stderr)
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
    while True:
        try:
            answer = input(
                f"Output file '{path.name}' already exists and is not empty. "
                "Overwrite? [y/N]: "
            ).strip().lower()
        except EOFError:
            print(
                "Error: input stream ended unexpectedly while waiting for overwrite confirmation.",
                file=sys.stderr,
            )
            return False

        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no", ""):
            return False
        print("Please answer 'y' or 'n'.")


def write_to_file(domains: Iterable[str], output_file: Path) -> bool:
    output_file = output_file.expanduser().resolve()

    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(
            f"Error creating directory for output file '{output_file.name}': {exc}",
            file=sys.stderr,
        )
        return False

    if output_file.exists():
        try:
            if output_file.stat().st_size > 0 and not confirm_overwrite(output_file):
                print("Aborted: output file will not be overwritten.", file=sys.stderr)
                return False
        except OSError as exc:
            print(
                f"Error checking output file '{output_file.name}': {exc}",
                file=sys.stderr,
            )
            return False

    try:
        with output_file.open("w", encoding="utf-8") as handle:
            for domain in sorted(domains):
                handle.write(domain + "\n")
    except OSError as exc:
        print(f"Error writing to file '{output_file.name}': {exc}", file=sys.stderr)
        return False

    print(f"Unique domain names have been written to '{output_file.name}'")
    return True


def output_to_console(domains: Iterable[str]) -> None:
    domains = sorted(domains)
    if not domains:
        print("No unique domains found to output.", file=sys.stderr)
        return

    print("Unique domain names:")
    for domain in domains:
        print(domain)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        description=(
            "Extract unique domain names from a file and optionally write "
            "them to an output file."
        )
    )
    parser.add_argument("-i", "--input", help="Input file path containing domain data.")
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path to save unique domain names. If omitted, results are printed to stdout.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.input:
        print("Error: provide -i/--input.", file=sys.stderr)
        return 1

    unique_domains = find_domains(Path(args.input))
    if not unique_domains:
        return 1

    if args.output:
        if not write_to_file(unique_domains, Path(args.output)):
            return 1
    else:
        output_to_console(unique_domains)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
