#!/usr/bin/env python3
import os
import sys
import subprocess
import xml.etree.ElementTree as ET
import argparse
import requests
from dataclasses import dataclass, field
from typing import List, Set
from rich.console import Console

DEBUG = False
NUMBERING = False
console = Console()

@dataclass
class HostCipherInfo:
    hostname: str
    ciphers: List[str] = field(default_factory=list)
    tls_versions: Set[str] = field(default_factory=set)

def print_banner() -> None:
    banner = (
        "[red]   _______       __                   __  __            __           [/red]\n"
        "[blue]  / ____(_)___  / /_  ___  __________/ / / /_  ______  / /____  _____[/blue]\n"
        "[red] / /   / / __ \\/ __ \\/ _ \\/ ___/ ___/ /_/ / / / / __ \\/ __/ _ \\/ ___/[/red]\n"
        "[blue]/ /___/ / /_/ / / / /  __/ /  (__  ) __  / /_/ / / / / /_/  __/ /    [/blue]\n"
        "[red]\\____/_/ .___/_/ /_/\\___/_/  /____/_/ /_/\\__,_/_/ /_/\\__/\\___/_/     [/red]\n"
        "[blue]      /_/                                                            [/blue]"
    )
    console.print(banner, markup=True)
    description="Scans domains for SSL/TLS cipher security using nmap and the ciphersuite.info API. Provide a domain list file (-d) or an nmap XML report (-x).\n"
    console.print(description, style="bold white")

def read_domains(file_path: str) -> List[str]:
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found.")
    with open(file_path, 'r', encoding='utf-8') as file:
        domains = [line.strip() for line in file if line.strip()]
    if not domains:
        raise ValueError("Domain list is empty!")
    return domains

def execute_nmap(domains: List[str], output_path: str, ports: str) -> None:
    print("[*] Running nmap on the following domains:")
    print("    " + ", ".join(domains))
    nmap_command = ["nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", ports, "-oX", output_path] + domains
    result = subprocess.run(nmap_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(f"[!] Warning: nmap exited with code {result.returncode}. Error: {result.stderr.decode().strip()}")
    else:
        print("[*] nmap completed successfully.")

def parse_nmap_output(file_path: str) -> List[HostCipherInfo]:
    try:
        tree = ET.parse(file_path)
    except ET.ParseError as e:
        raise ValueError(f"Error parsing XML file '{file_path}': {e}")
    root = tree.getroot()
    hosts_info: List[HostCipherInfo] = []
    for host in root.findall('host'):
        hostname_elem = host.find('./hostnames/hostname')
        hostname = hostname_elem.attrib.get('name', '-') if hostname_elem is not None else '-'
        ciphers: List[str] = []
        tls_versions: Set[str] = set()
        for script in host.findall(".//script[@id='ssl-enum-ciphers']"):
            for table in script.findall("table"):
                tls_version = table.attrib.get('key')
                if tls_version and (tls_version.startswith('TLS') or tls_version.startswith('SSL')):
                    tls_versions.add(tls_version)
                    ciphers_table = table.find("table[@key='ciphers']")
                    if ciphers_table is not None:
                        for cipher_table in ciphers_table.findall("table"):
                            cipher_elem = cipher_table.find("./elem[@key='name']")
                            if cipher_elem is not None and cipher_elem.text:
                                ciphers.append(cipher_elem.text)
        hosts_info.append(HostCipherInfo(hostname=hostname, ciphers=ciphers, tls_versions=tls_versions))
    if not hosts_info:
        print("[!] Warning: no hosts found in the XML output.")
    return hosts_info

def get_security_sets() -> dict:
    base_url = "https://ciphersuite.info/api"
    levels = ["insecure", "weak", "secure", "recommended"]
    security_sets = {}
    for level in levels:
        url = f"{base_url}/cs/security/{level}"
        ciphers_set = set()
        try:
            if DEBUG:
                print(f"[*] Querying API for level '{level}' via URL: {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            if "ciphersuites" in data:
                for item in data["ciphersuites"]:
                    for cipher_name, details in item.items():
                        if cipher_name:
                            ciphers_set.add(cipher_name)
                        if isinstance(details, dict):
                            openssl_name = details.get("openssl_name")
                            if openssl_name:
                                ciphers_set.add(openssl_name)
            if DEBUG:
                print(f"    [DEBUG] Received {len(ciphers_set)} ciphers for level '{level}'.")
        except Exception as e:
            print(f"[!] Error querying API for level '{level}': {e}")
        security_sets[level] = ciphers_set
    return security_sets

def is_cipher_safe(cipher: str, security_sets: dict) -> bool:
    if cipher in security_sets.get("insecure", set()) or cipher in security_sets.get("weak", set()):
        return False
    if cipher in security_sets.get("secure", set()) or cipher in security_sets.get("recommended", set()):
        return True
    return True

def check_ciphers_with_api(hosts_info: List[HostCipherInfo]) -> None:
    security_sets = get_security_sets()
    weak_ciphers_global = set()
    domain_weak_ciphers = {}
    domain_tls_weak = {}
    global_tls_versions = set()
    for host in hosts_info:
        global_tls_versions |= host.tls_versions
        weak_tls_for_domain = {tls for tls in host.tls_versions if tls not in {"TLSv1.2", "TLSv1.3"}}
        domain_tls_weak[host.hostname] = weak_tls_for_domain
        weak_for_domain = []
        if not host.ciphers:
            domain_weak_ciphers[host.hostname] = weak_for_domain
            continue
        print(f"[*] Processing domain: {host.hostname}")
        for cipher in host.ciphers:
            safe = is_cipher_safe(cipher, security_sets)
            if DEBUG:
                print(f"    [DEBUG] Cipher '{cipher}' is considered {'safe' if safe else 'unsafe'}.")
            if not safe:
                weak_for_domain.append(cipher)
                weak_ciphers_global.add(cipher)
        domain_weak_ciphers[host.hostname] = weak_for_domain
    global_weak_tls = sorted({tls for tls in global_tls_versions if tls not in {"TLSv1.2", "TLSv1.3"}})
    print("\n========== Final Report ==========\n")
    if global_weak_tls:
        print("TLS Versions below 1.2:")
        for tls in global_weak_tls:
            print(f"  - {tls}")
    else:
        print("No TLS versions below 1.2 detected.")
    print("\nWeak Unique Ciphers:\n")
    if weak_ciphers_global:
        sorted_weak_ciphers = sorted(weak_ciphers_global)
        if NUMBERING:
            for idx, cipher in enumerate(sorted_weak_ciphers, start=1):
                print(f"{idx}) {cipher}")
        else:
            for cipher in sorted_weak_ciphers:
                print(cipher)
    else:
        print("No weak ciphers detected.")
    print("\nDomain-wise Weak TLS Versions and Weak Ciphers:\n")
    for hostname in sorted(domain_weak_ciphers.keys()):
        print(f"{hostname}:")
        tls_weak_list = sorted(domain_tls_weak.get(hostname, []))
        if tls_weak_list:
            print("  Weak TLS/SSL Versions:")
            for idx, tls in enumerate(tls_weak_list, start=1):
                print(f"    {idx}) {tls}")
        else:
            print("  No weak TLS/SSL versions detected.")
        if domain_weak_ciphers[hostname]:
            print("  Weak Ciphers:")
            for idx, cipher in enumerate(sorted(set(domain_weak_ciphers[hostname])), start=1):
                print(f"    {idx}) {cipher}")
        else:
            print("  No weak ciphers detected.")
        print()

def main() -> None:
    print_banner()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domains", type=str, help="File containing a list of domains (one per line).")
    group.add_argument("-x", "--xml", type=str, help="nmap XML report file.")
    parser.add_argument("-p", "--ports", type=str, default="443", help="Ports to scan (comma-separated or '-' for all ports).")
    parser.add_argument("-debug", "--debug", action="store_true", help="Enable debug output.")
    parser.add_argument("-n", "--number", action="store_true", help="Enable numbering of weak ciphers in the global report.")
    args = parser.parse_args()
    global DEBUG, NUMBERING
    DEBUG = args.debug
    NUMBERING = args.number
    try:
        if args.xml:
            print("[*] Using provided nmap XML report.")
            hosts_info = parse_nmap_output(os.path.abspath(args.xml))
        else:
            print("[*] Using domain list. Starting nmap scan...")
            domains_file = os.path.abspath(args.domains)
            domains = read_domains(domains_file)
            output_file = os.path.join(os.path.dirname(domains_file), "domains.xml")
            execute_nmap(domains, output_file, args.ports)
            hosts_info = parse_nmap_output(output_file)
        check_ciphers_with_api(hosts_info)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
