#!/usr/bin/env python3
"""Extract unique open TCP ports from nmap XML and generate an httpx command."""

import argparse
import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

HTTPX_COMMAND_TEMPLATE = (
    "httpx -l scope.txt -sc -cl -ct -location -hash md5 -rt -lc -wc -title -server -td "
    "-method -ws -ip -cname -cdn -ss -system-chrome -sid 10 -p PORTS -pipeline -http2 "
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
        description="Extract unique open TCP ports from nmap XML and generate an httpx command."
    )
    parser.add_argument(
        'file',
        nargs='?',
        metavar='FILE',
        help="Path to the input nmap XML file (legacy positional argument)"
    )
    parser.add_argument(
        '-i', '--input',
        dest='input_file',
        help="Path to the input nmap XML file"
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


def host_is_up(host: ET.Element) -> bool:
    """Return True when the host is up or when status is absent."""
    status = host.find("status")
    if status is None:
        return True
    return (status.get("state") or "").lower() == "up"


def _extract_tcp_port(port: ET.Element) -> int | None:
    """Return an open TCP port number from an nmap <port> element."""
    protocol = (port.get("protocol") or "").lower()
    if protocol != "tcp":
        return None

    state_element = port.find("state")
    if state_element is None or state_element.get("state") != "open":
        return None

    portid = port.get("portid")
    if not portid:
        return None

    try:
        port_num = int(portid)
    except ValueError:
        logging.warning("Skipping non-numeric port identifier: %r", portid)
        return None

    if not (1 <= port_num <= 65535):
        logging.warning("Skipping out-of-range port: %s", port_num)
        return None

    return port_num


def extract_tcp_ports(file_path: str | Path) -> set[int]:
    """Read nmap XML and collect unique open TCP ports."""
    path = Path(file_path)
    tree = ET.parse(path)
    root = tree.getroot()
    tcp_ports: set[int] = set()

    for host in root.findall('host'):
        if not host_is_up(host):
            logging.debug("Skipping host because its state is not up.")
            continue

        for port in host.findall('./ports/port'):
            port_num = _extract_tcp_port(port)
            if port_num is None:
                continue
            tcp_ports.add(port_num)
            logging.debug("Found open tcp port: %s", port_num)

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
    except ET.ParseError as exc:
        logging.error("Failed to parse XML: %s", exc)
        return 1
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
