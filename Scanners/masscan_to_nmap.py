#!/usr/bin/env python3
"""Extract unique open TCP/UDP ports and generate matching nmap commands."""

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
        description="Extract unique open TCP/UDP ports and generate matching nmap commands."
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


def _extract_port_from_line(line: str) -> tuple[str, int] | None:
    discovered_match = RE_DISCOVERED.search(line)
    if discovered_match:
        return discovered_match.group(2).lower(), int(discovered_match.group(1))

    list_match = RE_LIST.search(line)
    if list_match:
        return list_match.group(1).lower(), int(list_match.group(2))

    return None


def _iter_lines(file_path: Path) -> Iterable[str]:
    with file_path.open('r', encoding='utf-8', errors='ignore') as handle:
        for line in handle:
            yield line.rstrip('\n')


def extract_ports(file_path: str | Path) -> dict[str, set[int]]:
    """
    Read the file and collect unique TCP/UDP ports from known masscan output formats.
    """
    path = Path(file_path)
    ports_by_protocol: dict[str, set[int]] = {"tcp": set(), "udp": set()}

    for line in _iter_lines(path):
        if not line or line.startswith("#"):
            continue

        try:
            result = _extract_port_from_line(line)
        except ValueError:
            logging.warning("Skipping invalid line: %r", line)
            continue

        if result is None:
            continue
        protocol, port = result
        if protocol not in ports_by_protocol:
            logging.debug("Skipping unsupported protocol %r in line: %r", protocol, line)
            continue
        if not (1 <= port <= 65535):
            logging.warning("Skipping out-of-range port: %s", port)
            continue

        ports_by_protocol[protocol].add(port)
        logging.debug("Found open %s port: %s", protocol, port)

    return ports_by_protocol


def generate_command(protocol: str, ports: set[int]) -> str:
    """Generate one nmap command for the given protocol and port list."""
    sorted_ports = sorted(ports)
    ports_str = ",".join(map(str, sorted_ports))

    if protocol == "udp":
        return (
            "sudo nmap -Pn -n -sUV --version-all --open "
            f"-p {ports_str} -v --webxml -oA nmap/nmap_result_udp -iL alive_ips4.txt"
        )

    return (
        "sudo nmap -Pn -n -sSV --version-all --open "
        f"-p {ports_str} --min-rate 4999 --max-rate 5000 --max-retries 1 "
        "--min-rtt-timeout 50ms --max-rtt-timeout 150ms "
        "-v --webxml -oA nmap/nmap_result -iL alive_ips4.txt"
    )


def format_commands_output(tcp_ports: set[int], udp_ports: set[int]) -> str:
    """Render generated commands in a readable, stable text format."""
    sections: list[str] = []

    if tcp_ports:
        sections.append(f"TCP Command:\n{generate_command('tcp', tcp_ports)}")
    if udp_ports:
        sections.append(f"UDP Command:\n{generate_command('udp', udp_ports)}")

    return "\n\n".join(sections)


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


def render_commands_with_copy_status(commands_output: str, copied: bool) -> str:
    """Prepend a green success line when clipboard copy succeeds."""
    if not copied:
        return commands_output
    return f"{COPY_SUCCESS_MESSAGE}\n{commands_output}"


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    file_path = Path(args.file).expanduser().resolve()
    if not file_path.is_file():
        logging.error("File not found: %s", file_path)
        return 1

    try:
        ports_by_protocol = extract_ports(file_path)
    except OSError as exc:
        logging.error("I/O error while reading %s: %s", file_path, exc)
        return 1

    tcp_ports = ports_by_protocol["tcp"]
    udp_ports = ports_by_protocol["udp"]
    if not tcp_ports and not udp_ports:
        logging.warning("No open TCP or UDP ports found.")
        return 0

    commands_output = format_commands_output(tcp_ports, udp_ports)
    copied = copy_to_clipboard(commands_output)
    if not copied:
        logging.warning(
            "Could not copy command to clipboard. Install pbcopy, wl-copy, xclip, xsel, or clip."
        )

    print(render_commands_with_copy_status(commands_output, copied))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
