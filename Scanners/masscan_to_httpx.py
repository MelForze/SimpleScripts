#!/usr/bin/env python3
"""Extract unique open TCP ports and generate an httpx command."""

import argparse
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Sequence


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

RE_DISCOVERED = re.compile(r"Discovered open port (\d+)/(\w+) on ", re.IGNORECASE)
RE_LIST = re.compile(r"^open\s+(\w+)\s+(\d+)\s+", re.IGNORECASE)
HTTPX_COMMAND_TEMPLATE = (
    "httpx -l scope.txt -sc -cl -ct -location -hash md5 -rt -lc -wc -title -server -td "
    "-method -ws -ip -cname -cdn -ss -sid 10 -t 100 -rl 300 -pa -p PORTS -pipeline -http2 "
    "-vhost -o ./httpx/httpx_result -oa -srd ./httpx/ -random-agent -auto-referer -fr -stats "
    "-timeout 30"
)
CLIPBOARD_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("pbcopy",),
    ("wl-copy",),
    ("xclip", "-selection", "clipboard"),
    ("xsel", "--clipboard", "--input"),
    ("clip.exe",),
    ("clip",),
)
GREEN = "\033[32m"
RESET = "\033[0m"
COPY_SUCCESS_MESSAGE = f"{GREEN}Команда скопирована в буфер обмена{RESET}"


def setup_logging(verbose: bool) -> None:
    """Configure logging: DEBUG if verbose, otherwise INFO."""
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = create_argument_parser(
        description="Extract unique open TCP ports and generate an httpx command."
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
    if args.file and args.input_file:
        parser.error("Use either FILE or -i/--input, not both.")
    resolved_input = args.input_file or args.file
    if not resolved_input:
        parser.error("Input file is required (use FILE or -i/--input).")
    args.file = resolved_input
    return args


def _iter_lines(file_path: Path) -> Iterable[str]:
    with file_path.open('r', encoding='utf-8', errors='ignore') as handle:
        for line in handle:
            yield line.rstrip('\n')


def _extract_tcp_port_from_line(line: str) -> int | None:
    discovered_match = RE_DISCOVERED.search(line)
    if discovered_match:
        protocol = discovered_match.group(2).lower()
        if protocol != "tcp":
            return None
        return int(discovered_match.group(1))

    list_match = RE_LIST.search(line)
    if list_match:
        protocol = list_match.group(1).lower()
        if protocol != "tcp":
            return None
        return int(list_match.group(2))

    return None


def extract_tcp_ports(file_path: str | Path) -> set[int]:
    """Read file and collect unique TCP ports from known masscan formats."""
    path = Path(file_path)
    tcp_ports: set[int] = set()

    for line in _iter_lines(path):
        if not line or line.startswith("#"):
            continue

        try:
            port = _extract_tcp_port_from_line(line)
        except ValueError:
            logging.warning("Skipping invalid line: %r", line)
            continue

        if port is None:
            continue
        if not (1 <= port <= 65535):
            logging.warning("Skipping out-of-range port: %s", port)
            continue

        tcp_ports.add(port)
        logging.debug("Found open tcp port: %s", port)

    return tcp_ports


def generate_command(tcp_ports: set[int]) -> str:
    """Generate httpx command with substituted and sorted TCP ports."""
    sorted_ports = sorted(tcp_ports)
    ports_str = ",".join(map(str, sorted_ports))
    return HTTPX_COMMAND_TEMPLATE.replace("PORTS", ports_str)


def copy_to_clipboard(text: str) -> bool:
    """Copy text to OS clipboard using the first available backend."""
    if not text:
        return False

    for command in CLIPBOARD_COMMANDS:
        executable = command[0]
        if shutil.which(executable) is None:
            continue
        try:
            subprocess.run(
                command,
                input=text,
                text=True,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            logging.debug("Clipboard backend failed: %s", executable)
            continue
        logging.debug("Copied to clipboard using backend: %s", executable)
        return True
    return False


def render_command_with_copy_status(command: str, copied: bool) -> str:
    """Prepend a green success line when clipboard copy succeeds."""
    if not copied:
        return command
    return f"{COPY_SUCCESS_MESSAGE}\n{command}"


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    file_path = Path(args.file).expanduser().resolve()
    if not file_path.is_file():
        logging.error("File not found: %s", file_path)
        return 1

    try:
        tcp_ports = extract_tcp_ports(file_path)
    except OSError as exc:
        logging.error("I/O error while reading %s: %s", file_path, exc)
        return 1

    if not tcp_ports:
        logging.warning("No open TCP ports found.")
        return 0

    command = generate_command(tcp_ports)
    copied = copy_to_clipboard(command)
    if not copied:
        logging.warning(
            "Could not copy command to clipboard. Install pbcopy, wl-copy, xclip, xsel, or clip."
        )

    print(render_command_with_copy_status(command, copied))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
