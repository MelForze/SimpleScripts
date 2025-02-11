#!/usr/bin/env python3
import socket
import ssl
import hashlib
import re
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress
from rich.console import Console

console = Console()

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

def get_certificate_fingerprint(host, port, hash_func='sha256', timeout=5):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
        if not cert_bin:
            return None
        hasher = hashlib.sha256 if hash_func == 'sha256' else hashlib.sha1
        return hasher(cert_bin).hexdigest()
    except Exception:
        return None

def parse_line(line):
    m = re.search(r'(\S+)\s*\[(.*?)\]', line)
    if not m:
        return None, []
    domain = m.group(1)
    ports = []
    for part in m.group(2).split(','):
        try:
            ports.append(int(part.strip()))
        except ValueError:
            continue
    return domain, ports

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

def process_file(filename, debug=False):
    tasks, results = [], {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                domain, ports = parse_line(line)
                if domain:
                    for port in ports:
                        tasks.append((domain, port))
    except Exception as e:
        console.print(f"Error processing file {filename}: {e}", style="bold red")
        return results
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
        usage="WildcardHunter.py [-h] (-s DOMAINS.txt) [-out OUTSCOPE.txt] [-debug] [-print] [-o OUTPUT]",
        add_help=False
    )
    parser.add_argument('-h', '--help', action=BannerHelpAction, help="Show help and exit.")
    parser.add_argument('-s', '--scope', required=True, help="Path to scope file")
    parser.add_argument('-out', '--outscope', required=True, help="Path to outscope file")
    parser.add_argument('-debug', action='store_true', help="Enable debug mode")
    parser.add_argument('-print', action='store_true', help="Print certificate fingerprint in output")
    parser.add_argument('-o', '--output', help="Path to output file for results")
    args = parser.parse_args()
    debug = args.debug
    print_fingerprint = args.print
    scope_file = args.scope
    outscope_file = args.outscope
    output_file = args.output

    print_banner()
    console.print("Processing scope domains...", style="bold blue")
    scope_data = process_file(scope_file, debug=debug)
    console.print("\nProcessing outscope domains...", style="bold blue")
    outscope_data = process_file(outscope_file, debug=debug)

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
            with open(output_file, 'w') as f:
                for line in output_messages:
                    f.write(line + "\n")
            console.print(f"Results written to {output_file}", style="bold green")
        except Exception as e:
            console.print(f"Error writing to file {output_file}: {e}", style="bold red")

if __name__ == '__main__':
    main()
