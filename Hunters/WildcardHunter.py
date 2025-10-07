#!/usr/bin/env python3
import socket
import ssl
import hashlib
import re
import argparse
import unicodedata
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress
from rich.console import Console

console = Console()

# Map various Unicode dash and dot characters to ASCII
_DASH_MAP = dict.fromkeys(map(ord, ["\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212"]), "-")
_DOT_MAP  = dict.fromkeys(map(ord, ["\u3002", "\uFF0E", "\uFF61"]), ".")

def print_banner():
    banner = (
        "[red] _       ___ __    __                    ____  __            __           [/red]\n"
        "[blue]| |     / (_) /___/ /________ __________/ / / / /_  ______  / /____  _____[/blue]\n"
        "[red]| | /| / / / / __  / ___/ __ `/ ___/ __  / /_/ / / / / __ \\/ __/ _ \\/ ___/[/red]\n"
        "[blue]| |/ |/ / / / /_/ / /__/ /_/ / /  / /_/ / __  / /_/ / / / / /_/  __/ /    [/blue]\n"
        "[red]|__/|__/_/_/\\__,_/\\___/\\__,_/_/   \\__,_/_/ /_/\\__,_/_/ /_/\\__/\\___/_/     [/red]\n"
        "[blue]                                                                     [/blue]"
    )
    console.print(banner, markup=True)
    console.print("This script compares SSL certificate fingerprints and detects certificate reuse between domains. Optionally, results can be written to an output file.\n", style="bold white")

class BannerHelpAction(argparse._HelpAction):
    def __call__(self, parser, namespace, values, option_string=None):
        print_banner()
        parser.print_help()
        parser.exit()

def _to_alabel(domain: str) -> str:
    """
    Normalize and convert a Unicode or malformed punycode domain to A-label (ASCII).
    - NFC normalize
    - unify non-ASCII dashes to '-'
    - unify non-ASCII dots to '.'
    - fix 'xn-' -> 'xn--' on label boundaries
    - lower-case and strip trailing dot
    - prefer UTS#46 via 'idna' package if available; fallback to built-in 'idna' codec
    """
    if not domain:
        return domain

    s = domain.strip()
    # Normalize Unicode and unify separators
    s = unicodedata.normalize("NFC", s)
    s = s.translate(_DASH_MAP).translate(_DOT_MAP)
    s = s.rstrip(".").lower()

    # Fix bad ACE prefix: turn 'xn-' (single hyphen) into 'xn--' on label boundaries
    s = re.sub(r'(?i)(^|\.)(xn-)(?!-)', lambda m: m.group(1) + 'xn--', s)

    # Convert to IDNA A-label (ACE). Prefer UTS#46 from the 'idna' package.
    try:
        import idna  # type: ignore
        alabel = idna.encode(s, uts46=True, std3_rules=True).decode("ascii")
    except Exception:
        alabel = s.encode("idna").decode("ascii")
    return alabel

def get_certificate_fingerprint(host, port, hash_func='sha256', timeout=5):
    try:
        # Always convert host to A-label for DNS + SNI
        alabel_host = _to_alabel(host)
        context = ssl.create_default_context()
        with socket.create_connection((alabel_host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=alabel_host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
        if not cert_bin:
            return None
        hasher = hashlib.sha256 if hash_func == 'sha256' else hashlib.sha1
        return hasher(cert_bin).hexdigest()
    except Exception:
        return None

def parse_line(line):
    """
    Parse a 'host [p1, p2, ...]' line. If no bracketed ports are present, return host with an empty port list.
    """
    m = re.search(r'(\S+)\s*$begin:math:display$(.*?)$end:math:display$', line)
    if not m:
        host = line.strip()
        return (host if host else None), []
    domain = m.group(1)
    ports = []
    for part in m.group(2).split(','):
        try:
            ports.append(int(part.strip()))
        except ValueError:
            continue
    return domain, ports

def _dedupe_keep_order(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def _normalize_ports(port_list):
    """Validate and normalize a list of ports to ints in [1..65535], de-duplicated but order-preserving."""
    out = []
    for p in port_list or []:
        try:
            ip = int(p)
            if 1 <= ip <= 65535:
                out.append(ip)
        except Exception:
            continue
    return _dedupe_keep_order(out)

def parse_ports_arg(ports_str):
    """Parse CLI --ports like '443,80,8080' into a list of ints. Return [] if not provided or invalid."""
    if not ports_str:
        return []
    parts = re.split(r'[,\s]+', ports_str.strip())
    return _normalize_ports(parts)

def load_entries_from_yaml(path, cli_ports):
    """
    Load entries from a YAML file.
    Supported shapes:
      - mapping: {host: [ports] | port | null}
      - list of scalars: [host1, host2]
      - list of mappings: [{'host': name, 'ports': [..]}] or [{host: [..]}, ...]
    For each entry:
      - If ports are defined in YAML, use them.
      - Else if CLI --ports provided, use those.
      - Else use default [443].
    """
    try:
        import yaml  # type: ignore
    except Exception as e:
        raise RuntimeError("PyYAML is required to read YAML files. Install it with 'pip install pyyaml'.") from e

    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    entries = []  # list of (host, [ports])
    default_ports = _normalize_ports(cli_ports) or [443]

    def add(host, ports_from_yaml):
        host = (host or '').strip()
        if not host:
            return
        if ports_from_yaml is None:
            ports = default_ports
        else:
            ports = _normalize_ports(ports_from_yaml)
            ports = ports or default_ports
        entries.append((host, ports))

    if isinstance(data, dict):
        for host, val in data.items():
            if isinstance(val, list):
                add(host, val)
            elif isinstance(val, int) or (isinstance(val, str) and val.isdigit()):
                add(host, [int(val)])
            elif val is None:
                add(host, None)
            elif isinstance(val, dict) and 'ports' in val:
                add(host, val.get('ports'))
            else:
                # Fallback: treat as no ports
                add(host, None)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                add(item, None)
            elif isinstance(item, dict):
                # Try common keys
                host = item.get('host') or item.get('domain') or item.get('ip') or None
                if host is None and len(item) == 1:
                    # form like {'example.com': [80,443]}
                    host, val = next(iter(item.items()))
                    if isinstance(val, list):
                        add(host, val)
                    elif isinstance(val, int) or (isinstance(val, str) and str(val).isdigit()):
                        add(host, [int(val)])
                    elif val is None:
                        add(host, None)
                    elif isinstance(val, dict) and 'ports' in val:
                        add(host, val.get('ports'))
                    else:
                        add(host, None)
                else:
                    add(host, item.get('ports'))
            else:
                # Unknown item type: ignore
                continue
    else:
        # Unsupported top-level YAML type, ignore
        pass

    # Expand to tasks: (host, port)
    tasks = []
    for host, ports in entries:
        for p in ports:
            tasks.append((host, p))
    return tasks

def load_entries_from_text(path, cli_ports):
    """
    Load entries from a text file that may contain either:
      - 'host [80,443]' lines (explicit ports), or
      - plain 'host' lines (no ports).
    For lines with no explicit ports:
      - If CLI --ports provided, use those.
      - Else use default [443].
    """
    tasks = []
    default_ports = _normalize_ports(cli_ports) or [443]

    with open(path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            host, ports = parse_line(line)
            if host is None:
                continue
            if ports:
                ports_n = _normalize_ports(ports)
                ports_n = ports_n or default_ports
                for p in ports_n:
                    tasks.append((host, p))
            else:
                for p in default_ports:
                    tasks.append((host, p))
    return tasks

def load_tasks_from_file(path, cli_ports):
    """
    Dispatch loader based on file extension (.yaml/.yml -> YAML; otherwise text).
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.yaml', '.yml'):
        return load_entries_from_yaml(path, cli_ports)
    else:
        return load_entries_from_text(path, cli_ports)

def process_tasks(tasks, filename, debug=False):
    results = {}
    total = len(tasks)
    if total == 0:
        console.print(f"File {filename} does not contain valid tasks.", style="bold yellow")
        return results
    console.print(f"\nProcessing file {filename} ({total} tasks):", style="bold blue")
    with Progress() as progress:
        task_progress = progress.add_task(f"[cyan]Processing tasks from {filename}...", total=total)
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_task = {executor.submit(process_task, task, filename, debug): task for task in tasks}
            for future in as_completed(future_to_task):
                domain, port, fp = future.result()
                if fp:
                    results.setdefault(fp, []).append((domain, port))
                progress.advance(task_progress)
    return results

def process_task(task, filename, debug):
    domain, port = task
    if debug:
        console.print(f"[{filename}] Checking {domain}:{port} ...", style="dim")
    fp = get_certificate_fingerprint(domain, port)
    if debug:
        if fp:
            console.print(f"  Fingerprint received: {fp}", style="green")
        else:
            console.print(f"  Failed to retrieve certificate for {domain}:{port}", style="red")
    return domain, port, fp

def preprocess_outscope_data(outscope_data, scope_domains):
    new_data = {}
    for fp, entries in outscope_data.items():
        unique_entries = set(entries)
        filtered = [entry for entry in unique_entries if entry[0] not in scope_domains]
        if filtered:
            new_data[fp] = filtered
    return new_data

def main():
    parser = argparse.ArgumentParser(
        usage="WildcardHunter.py [-h] (-s SCOPE.{txt|yaml|yml}) [-out OUTSCOPE.{txt|yaml|yml}] [-p PORTS] [-debug] [-print] [-o OUTPUT]",
        add_help=False
    )
    parser.add_argument('-h', '--help', action=BannerHelpAction, help="Show help and exit.")
    parser.add_argument('-s', '--scope', required=True, help="Path to scope file (.txt, .yaml, or .yml)")
    parser.add_argument('-out', '--outscope', required=True, help="Path to outscope file (.txt, .yaml, or .yml)")
    parser.add_argument('-p', '--ports', help="Comma-separated list of ports to scan when ports are not specified in input files, e.g. '443,80,8443'")
    parser.add_argument('-debug', action='store_true', help="Enable debug mode")
    parser.add_argument('-print', action='store_true', help="Print certificate fingerprint in output")
    parser.add_argument('-o', '--output', help="Path to output file for results")
    args = parser.parse_args()

    debug = args.debug
    print_fingerprint = args.print
    output_file = args.output
    cli_ports = parse_ports_arg(args.ports)

    print_banner()
    console.print("Loading scope tasks...", style="bold blue")
    try:
        scope_tasks = load_tasks_from_file(args.scope, cli_ports)
    except Exception as e:
        console.print(f"Error reading scope file {args.scope}: {e}", style="bold red")
        return

    console.print("\nLoading outscope tasks...", style="bold blue")
    try:
        outscope_tasks = load_tasks_from_file(args.outscope, cli_ports)
    except Exception as e:
        console.print(f"Error reading outscope file {args.outscope}: {e}", style="bold red")
        return

    console.print("\nProcessing scope domains...", style="bold blue")
    scope_data = process_tasks(scope_tasks, args.scope, debug=debug)

    console.print("\nProcessing outscope domains...", style="bold blue")
    outscope_data = process_tasks(outscope_tasks, args.outscope, debug=debug)

    scope_domains = {domain for entries in scope_data.values() for (domain, _) in entries}
    outscope_data = preprocess_outscope_data(outscope_data, scope_domains)

    console.print("\nComparing certificates:", style="bold magenta")
    printed = set()
    output_messages = []
    for fp, scope_entries in scope_data.items():
        if fp in outscope_data:
            for s_entry in scope_entries:
                for o_entry in outscope_data[fp]:
                    message = (f"[+] Certificate {fp} at {s_entry[0]}:{s_entry[1]} also found at {o_entry[0]}:{o_entry[1]}"
                               if print_fingerprint
                               else f"[+] Certificate at {s_entry[0]}:{s_entry[1]} also found at {o_entry[0]}:{o_entry[1]}")
                    if message not in printed:
                        console.print(message, style="bold green")
                        printed.add(message)
                        output_messages.append(message)

    if not printed:
        message = "No certificate reuses found."
        console.print(message, style="bold yellow")
        output_messages.append(message)
    else:
        message = f"Total certificate reuses found: {len(printed)}"
        console.print(message, style="bold cyan")
        output_messages.append(message)

    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for line in output_messages:
                    f.write(line + "\n")
            console.print(f"Results written to {output_file}", style="bold green")
        except Exception as e:
            console.print(f"Error writing to file {output_file}: {e}", style="bold red")

if __name__ == '__main__':
    main()