#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")
ENABLED_RE = re.compile(r"\(\s*status\s*=\s*Enabled\s*\)", re.IGNORECASE)


def create_argument_parser(*args, **kwargs) -> argparse.ArgumentParser:
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


@dataclass
class SplitStats:
    parsed: int = 0
    written: int = 0
    skipped_empty: int = 0
    skipped_disabled: int = 0
    skipped_invalid: int = 0
    skipped_machine: int = 0


def build_parser() -> argparse.ArgumentParser:
    parser = create_argument_parser(
        description=(
            "Split a text NTDS/secretsdump-like dump into aligned usernames.txt "
            "and nthashes.txt files. By default only (status=Enabled) accounts are written."
        )
    )
    parser.add_argument(
        "ntds",
        type=Path,
        help="Input text dump, for example DOMAIN\\user:rid:lmhash:nthash::: ... (status=Enabled)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Directory for usernames.txt and nthashes.txt. Default: current directory.",
    )
    parser.add_argument(
        "-kp",
        "--keep-domain",
        action="store_true",
        help="Keep DOMAIN\\ prefix in usernames.txt.",
    )
    parser.add_argument(
        "-id",
        "--include-disabled",
        action="store_true",
        help="Do not require (status=Enabled).",
    )
    parser.add_argument(
        "-sm",
        "--skip-machine",
        action="store_true",
        help="Skip machine accounts whose username ends with '$'.",
    )
    return parser


def strip_domain(username: str) -> str:
    """Return username without DOMAIN\\ prefix."""
    if "\\" in username:
        return username.rsplit("\\", 1)[1]
    return username


def parse_ntds_line(
    line: str,
    *,
    keep_domain: bool,
    include_disabled: bool,
    skip_machine: bool,
    stats: SplitStats,
) -> tuple[str, str] | None:
    """Parse one secretsdump-like line and return (username, nthash) when usable."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        stats.skipped_empty += 1
        return None

    stats.parsed += 1
    if not include_disabled and not ENABLED_RE.search(stripped):
        stats.skipped_disabled += 1
        return None

    fields = stripped.split(":")
    if len(fields) < 4:
        stats.skipped_invalid += 1
        return None

    raw_username = fields[0].strip()
    nthash = fields[3].strip().lower()
    username = raw_username if keep_domain else strip_domain(raw_username)

    if not username or not HEX32_RE.fullmatch(nthash):
        stats.skipped_invalid += 1
        return None

    if skip_machine and username.endswith("$"):
        stats.skipped_machine += 1
        return None

    return username, nthash


def split_ntds(
    input_path: Path,
    output_dir: Path,
    *,
    keep_domain: bool = False,
    include_disabled: bool = False,
    skip_machine: bool = False,
) -> SplitStats:
    """Write usernames.txt and nthashes.txt from a text NTDS dump."""
    stats = SplitStats()
    output_dir.mkdir(parents=True, exist_ok=True)
    usernames_path = output_dir / "usernames.txt"
    hashes_path = output_dir / "nthashes.txt"

    with input_path.open("r", encoding="utf-8", errors="ignore") as source, usernames_path.open(
        "w",
        encoding="utf-8",
    ) as usernames, hashes_path.open("w", encoding="utf-8") as hashes:
        for line in source:
            parsed = parse_ntds_line(
                line,
                keep_domain=keep_domain,
                include_disabled=include_disabled,
                skip_machine=skip_machine,
                stats=stats,
            )
            if parsed is None:
                continue
            username, nthash = parsed
            usernames.write(username + "\n")
            hashes.write(nthash + "\n")
            stats.written += 1

    return stats


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    input_path = Path(str(args.ntds)).expanduser()
    output_dir = Path(str(args.output_dir)).expanduser()

    if not input_path.is_file():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        stats = split_ntds(
            input_path,
            output_dir,
            keep_domain=args.keep_domain,
            include_disabled=args.include_disabled,
            skip_machine=args.skip_machine,
        )
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(
        "Summary: "
        f"parsed={stats.parsed} "
        f"written={stats.written} "
        f"skipped_empty={stats.skipped_empty} "
        f"skipped_disabled={stats.skipped_disabled} "
        f"skipped_invalid={stats.skipped_invalid} "
        f"skipped_machine={stats.skipped_machine}"
    )
    print(f"Wrote: {output_dir / 'usernames.txt'}")
    print(f"Wrote: {output_dir / 'nthashes.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
