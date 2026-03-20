#!/usr/bin/env python3

import argparse
import sys
from collections import Counter
from pathlib import Path


DEFAULT_COMPROMISED_OUTPUT = "compromised.txt"
DEFAULT_USER_PASS_OUTPUT = "user-pass.txt"


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def try_load_rich():
    try:
        from rich.console import Console
        from rich.table import Table
    except ModuleNotFoundError:
        return None, None

    return Console(), Table


def load_rich():
    console, table_cls = try_load_rich()
    if console is None or table_cls is None:
        raise RuntimeError(
            "Missing dependency: install 'rich' to use WeakPassHunter."
        )
    return console, table_cls


def print_banner(console) -> None:
    lines = [
        "[red] _       __           __   ____                  __  __            __           [/red]",
        "[blue]| |     / /__  ____ _/ /__/ __ \\____ ___________/ / / /_  ______  / /____  _____[/blue]",
        "[red]| | /| / / _ \\/ __ `/ //_/ /_/ / __ `/ ___/ ___/ /_/ / / / / __ \\/ __/ _ \\/ ___/[/red]",
        "[blue]| |/ |/ /  __/ /_/ / ,< / ____/ /_/ (__  |__  ) __  / /_/ / / / / /_/  __/ /    [/blue]",
        "[red]|__/|__/\\___/\\__,_/_/|_/_/    \\__,_/____/____/_/ /_/\\__,_/_/ /_/\\__/\\___/_/     [/red]",
        "[blue]                                                                                [/blue]",
    ]
    for line in lines:
        console.print(line, markup=True)

    description = (
        "This script outputs the number of cracked passwords and the top 5 "
        "most frequent passwords. It processes a file containing lines in the "
        "format: domain\\username:nthash:password or username:nthash:password."
    )
    console.print("\n" + description, style="bold white")


def process_input(lines):
    total_accounts = 0
    password_counter = Counter()
    compromised_entries = []

    for line in lines:
        line = line.rstrip("\n")
        if not line:
            continue

        parts = line.split(":", 2)
        if len(parts) != 3:
            continue

        login = parts[0]
        username = login.split("\\")[-1] if "\\" in login else login
        password = parts[2]
        if password.strip() == "":
            password = ""

        total_accounts += 1
        password_counter[password] += 1
        compromised_entries.append((username, password))

    return total_accounts, password_counter, compromised_entries


def write_saved_results(
    compromised_entries,
    compromised_output=DEFAULT_COMPROMISED_OUTPUT,
    user_pass_output=DEFAULT_USER_PASS_OUTPUT,
):
    compromised_path = Path(compromised_output)
    user_pass_path = Path(user_pass_output)
    compromised_path.parent.mkdir(parents=True, exist_ok=True)
    user_pass_path.parent.mkdir(parents=True, exist_ok=True)

    with compromised_path.open("w", encoding="utf-8") as compromised_file:
        seen = set()
        for username, _ in compromised_entries:
            if username not in seen:
                compromised_file.write(username + "\n")
                seen.add(username)

    with user_pass_path.open("w", encoding="utf-8") as user_pass_file:
        for username, password in compromised_entries:
            user_pass_file.write(f"{username}:{password}\n")


def build_parser():
    parser = create_argument_parser(
        usage="%(prog)s [options]",
        add_help=False,
        description="WeakpassHunter utility",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        required=False,
        help="Path to the file with hashes. If omitted, reads from standard input.",
    )
    parser.add_argument(
        "-t",
        "--top",
        type=int,
        default=5,
        help="Number of top frequent passwords to display (default: 5)",
    )
    parser.add_argument(
        "-s",
        "--save",
        action="store_true",
        help=(
            "Save compromised usernames to 'compromised.txt' and user:password "
            "pairs to 'user-pass.txt'"
        ),
    )
    parser.add_argument(
        "--compromised-output",
        default=DEFAULT_COMPROMISED_OUTPUT,
        help=(
            "Output path for compromised usernames when --save is used "
            f"(default: {DEFAULT_COMPROMISED_OUTPUT})."
        ),
    )
    parser.add_argument(
        "--user-pass-output",
        default=DEFAULT_USER_PASS_OUTPUT,
        help=(
            "Output path for username:password pairs when --save is used "
            f"(default: {DEFAULT_USER_PASS_OUTPUT})."
        ),
    )
    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        help="Show this help message and exit",
    )
    return parser


def main(argv=None) -> int:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if not argv_list:
        parser.print_help()
        return 0

    args = parser.parse_args(argv_list)

    if args.help:
        console, _ = try_load_rich()
        if console is not None:
            print_banner(console)
            console.print("")
        parser.print_help()
        return 0

    try:
        console, table_cls = load_rich()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_banner(console)
    console.print("")

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError as exc:
            print(f"Error opening file {args.file}: {exc}", file=sys.stderr)
            return 1
    else:
        lines = sys.stdin.readlines()

    total_accounts, password_counter, compromised_entries = process_input(lines)
    effective_top = min(args.top, len(password_counter))

    console.print("\n" + "=" * 60 + "\n", style="bold white")
    console.print(
        "Cracked passwords count: " + str(total_accounts),
        style="bold green",
    )
    console.print(
        "\nTop {} most frequent passwords:".format(effective_top),
        style="bold green",
    )
    console.print("")

    table = table_cls(show_header=True, header_style="bold", show_edge=True)
    table.add_column("Password", no_wrap=True)
    table.add_column("Count", justify="right")

    for password, count in password_counter.most_common(effective_top):
        display_pass = password if password != "" else "<empty>"
        table.add_row(display_pass, str(count))

    console.print(table)
    console.print("")

    if args.save:
        try:
            write_saved_results(
                compromised_entries,
                compromised_output=args.compromised_output,
                user_pass_output=args.user_pass_output,
            )
        except OSError as exc:
            print(f"Error saving files: {exc}", file=sys.stderr)
            return 1

        console.print(
            "Saved compromised usernames to '{}' and user:password pairs to '{}'.".format(
                args.compromised_output,
                args.user_pass_output,
            ),
            style="bold yellow",
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
