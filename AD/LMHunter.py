#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path


EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
DEFAULT_USERS_OUTPUT = "lm.txt"
DEFAULT_FULL_OUTPUT = "lm_full.txt"


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def display_banner():
    print(
        """
██╗░░░░░███╗░░░███╗██╗░░██╗██╗░░░██╗███╗░░██╗████████╗███████╗██████╗░
██║░░░░░████╗░████║██║░░██║██║░░░██║████╗░██║╚══██╔══╝██╔════╝██╔══██╗
██║░░░░░██╔████╔██║███████║██║░░░██║██╔██╗██║░░░██║░░░█████╗░░██████╔╝
██║░░░░░██║╚██╔╝██║██╔══██║██║░░░██║██║╚████║░░░██║░░░██╔══╝░░██╔══██╗
███████╗██║░╚═╝░██║██║░░██║╚██████╔╝██║░╚███║░░░██║░░░███████╗██║░░██║
╚══════╝╚═╝░░░░░╚═╝╚═╝░░╚═╝░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝

Welcome to the LMHunteR Script!
"""
    )


def parse_arguments(argv=None):
    parser = create_argument_parser(
        description=(
            "Read an input file and create two output files:\n"
            "1. lm.txt - contains only the usernames.\n"
            "2. lm_full.txt - contains full lines where the LM hash is not "
            f"equal to '{EMPTY_LM_HASH}'."
        ),
        usage="./lm_hunter.py <file_path>",
    )
    parser.add_argument("file_path", type=str, help="Path to the input file")
    parser.add_argument(
        "--users-output",
        default=DEFAULT_USERS_OUTPUT,
        help=f"Path for usernames output (default: {DEFAULT_USERS_OUTPUT}).",
    )
    parser.add_argument(
        "--full-output",
        default=DEFAULT_FULL_OUTPUT,
        help=f"Path for full-line output (default: {DEFAULT_FULL_OUTPUT}).",
    )
    return parser.parse_args(argv)


def iter_detected_entries(lines):
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split(":")
        if len(parts) < 3:
            continue

        username_domain = parts[0]
        lm_hash = parts[2].strip().lower()
        if lm_hash == EMPTY_LM_HASH:
            continue

        username = username_domain.split("\\")[-1] if "\\" in username_domain else username_domain
        yield username, line


def filter_file(
    input_file,
    usernames_output=DEFAULT_USERS_OUTPUT,
    full_output=DEFAULT_FULL_OUTPUT,
):
    input_path = Path(input_file)
    users_path = Path(usernames_output)
    full_path = Path(full_output)
    users_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.parent.mkdir(parents=True, exist_ok=True)

    line_count = 0
    with input_path.open("r", encoding="utf-8", errors="replace") as in_file:
        with users_path.open("w", encoding="utf-8") as usernames_file:
            with full_path.open("w", encoding="utf-8") as full_file:
                for username, line in iter_detected_entries(in_file):
                    full_file.write(line + "\n")
                    usernames_file.write(username + "\n")
                    line_count += 1

    return line_count


def main(argv=None) -> int:
    display_banner()
    args = parse_arguments(argv)
    input_path = Path(args.file_path).expanduser().resolve()
    users_output_path = Path(args.users_output).expanduser().resolve()
    full_output_path = Path(args.full_output).expanduser().resolve()

    if not input_path.is_file():
        print(f"Error: File '{input_path}' not found.", file=sys.stderr)
        return 1

    try:
        line_count = filter_file(
            input_path,
            usernames_output=args.users_output,
            full_output=args.full_output,
        )
    except OSError as exc:
        print(f"Error processing files: {exc}", file=sys.stderr)
        return 1

    print(f"\nNumber of detected lines: {line_count}")
    print(f"Saved usernames to: {users_output_path}")
    print(f"Saved matching lines to: {full_output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
