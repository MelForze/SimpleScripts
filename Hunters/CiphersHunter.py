#!/usr/bin/env python3
import os
import sys
import subprocess
import xml.etree.ElementTree as ET
import argparse
import requests
import socket
import ipaddress
import json
from dataclasses import dataclass, field
from typing import List, Set
from rich.console import Console

DEBUG = False
NUMBERING = False
console = Console()
report_lines: List[str] = []

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CIPHER_CACHE_PATH = os.path.join(SCRIPT_DIR, "ciphers_cache.json")

def log(msg: str, style: str = None, highlight: bool = False) -> None:
    plain = msg.replace("[red]", "").replace("[green]", "").replace("[/red]", "").replace("[/green]", "")
    report_lines.append(plain)
    if style:
        console.print(msg, style=style, highlight=highlight)
    else:
        console.print(msg, highlight=highlight)

@dataclass
class HostCipherInfo:
    hostname: str
    ciphers: List[str] = field(default_factory=list)
    tls_versions: Set[str] = field(default_factory=set)
    cert_cn: str = ""

def print_banner() -> None:
    banner = (
        "[red]   _______       __                   __  __            __           [/red]\n"
        "[blue]  / ____(_)___  / /_  ___  __________/ / / /_  ______  / /____  _____[/blue]\n"
        "[red] / /   / / __ \\/ __ \\/ _ \\/ ___/ ___/ /_/ / / / / __ \\/ __/ _ \\/ ___/[/red]\n"
        "[blue]/ /___/ / /_/ / / / /  __/ /  (__  ) __  / /_/ / / / / /_/  __/ /    [/blue]\n"
        "[red]\\____/_/ .___/_/ /_/\\___/_/  /____/_/ /_/\\__,_/_/ /_/\\__/\\___/_/     [/red]\n"
        "[blue]      /_/                                                            [/blue]\n"
    )
    console.print(banner, markup=True, highlight=False)
    description = ("Scans domains for SSL/TLS cipher security using nmap and the ciphersuite.info API. "
                   "Provide a domain list file (-d) or an nmap XML report (-x).\n")
    console.print(description, style="bold white", highlight=False)

def read_domains(file_path: str) -> List[str]:
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found.")
    domain_targets = set()
    ip_targets = set()
    subnet_targets = set()
    network_objects = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            if "/" in line:
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    subnet_str = str(net)
                    if subnet_str not in subnet_targets:
                        subnet_targets.add(subnet_str)
                        network_objects.append(net)
                except Exception:
                    domain_targets.add(line)
            else:
                try:
                    ip_obj = ipaddress.ip_address(line)
                    if any(ip_obj in net for net in network_objects):
                        continue
                    ip_targets.add(str(ip_obj))
                except ValueError:
                    domain_targets.add(line)
    targets = list(domain_targets) + list(subnet_targets) + list(ip_targets)
    if not targets:
        raise ValueError("Domain list is empty!")
    return targets

def execute_nmap(domains: List[str], output_path: str, ports: str) -> None:
    log("[*] Running nmap on the following targets:", highlight=False)
    log("    " + ", ".join(domains), highlight=False)
    nmap_command = ["nmap","-Pn", "-sV", "--script", "ssl-enum-ciphers,ssl-cert", "-p", ports, "-oX", output_path] + domains
    result = subprocess.run(nmap_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode != 0:
        log(f"[!] Warning: nmap exited with code {result.returncode}. Error: {result.stderr.decode().strip()}", style="red", highlight=False)
    else:
        log("[*] nmap completed successfully.", highlight=False)

def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def resolve_hostname(ip_addr: str) -> str:
    try:
        resolved = socket.gethostbyaddr(ip_addr)[0]
        return resolved
    except Exception:
        return ip_addr

def certificate_matches_domain(cert_cn: str, domain: str) -> bool:
    cert_cn = cert_cn.lower()
    domain = domain.lower()
    if cert_cn.startswith("*."):
        base = cert_cn[2:]
        return domain.endswith(base)
    else:
        return cert_cn == domain

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
        if hostname == '-' or is_ip_address(hostname):
            address_elem = host.find('address')
            if address_elem is not None:
                ip_addr = address_elem.attrib.get('addr')
                if ip_addr:
                    hostname = resolve_hostname(ip_addr)
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
        cert_cn = ""
        for port in host.findall('ports/port'):
            ssl_cert_script = port.find("script[@id='ssl-cert']")
            if ssl_cert_script is not None:
                subject_table = ssl_cert_script.find("table[@key='subject']")
                if subject_table is not None:
                    commonName_elem = subject_table.find("elem[@key='commonName']")
                    if commonName_elem is not None and commonName_elem.text:
                        cert_cn = commonName_elem.text.strip()
                        break
        hosts_info.append(HostCipherInfo(hostname=hostname, ciphers=ciphers, tls_versions=tls_versions, cert_cn=cert_cn))
    if not hosts_info:
        log("[!] Warning: no hosts found in the XML output.", style="red", highlight=False)
    return hosts_info

def get_security_sets(update: bool = False) -> dict:
    if not update and os.path.exists(CIPHER_CACHE_PATH):
        try:
            with open(CIPHER_CACHE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for level in data:
                data[level] = set(data[level])
            log(f"[*] Cipher cache loaded from {CIPHER_CACHE_PATH}", style="green", highlight=False)
            return data
        except Exception as e:
            log(f"[!] Failed to load cipher cache: {e}", style="red", highlight=False)
    base_url = "https://ciphersuite.info/api"
    levels = ["insecure", "weak", "secure", "recommended"]
    security_sets = {}
    for level in levels:
        url = f"{base_url}/cs/security/{level}"
        ciphers_set = set()
        try:
            if DEBUG:
                log(f"[*] Querying API for level '{level}' via URL: {url}", style="green", highlight=False)
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
                log(f"    [DEBUG] Received {len(ciphers_set)} ciphers for level '{level}'.", style="green", highlight=False)
        except Exception as e:
            log(f"[!] Error querying API for level '{level}': {e}", style="red", highlight=False)
        security_sets[level] = ciphers_set
    try:
        with open(CIPHER_CACHE_PATH, "w", encoding="utf-8") as f:
            out_data = {level: list(security_sets[level]) for level in security_sets}
            json.dump(out_data, f, ensure_ascii=False, indent=2)
        log(f"[*] Cipher cache saved to {CIPHER_CACHE_PATH}", style="green", highlight=False)
    except Exception as e:
        log(f"[!] Could not save cipher cache: {e}", style="red", highlight=False)
    return security_sets

def is_cipher_safe(cipher: str, security_sets: dict) -> bool:
    if cipher in security_sets.get("insecure", set()) or cipher in security_sets.get("weak", set()):
        return False
    if cipher in security_sets.get("secure", set()) or cipher in security_sets.get("recommended", set()):
        return True
    return True

def check_ciphers_with_api(hosts_info: List[HostCipherInfo], update: bool) -> None:
    security_sets = get_security_sets(update)
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
        else:
            log(f"[*] Processing target: [bold white]{host.hostname}[/bold white]", highlight=False)
            for cipher in host.ciphers:
                safe = is_cipher_safe(cipher, security_sets)
                if DEBUG:
                    log(f"    [DEBUG] Cipher '{cipher}' is considered {'safe' if safe else 'unsafe'}.", style="green" if safe else "red", highlight=False)
                if not safe:
                    weak_for_domain.append(cipher)
                    weak_ciphers_global.add(cipher)
            domain_weak_ciphers[host.hostname] = weak_for_domain

    log("\n========== Final Report ==========\n", style="bold white", highlight=False)
    if global_tls_versions - {"TLSv1.2", "TLSv1.3"}:
        log("TLS Versions below 1.2:\n", style="bold white", highlight=False)
        for tls in sorted(global_tls_versions - {"TLSv1.2", "TLSv1.3"}):
            log(f"{tls}", style="red", highlight=False)
    else:
        log("No TLS versions below 1.2 detected.", style="green", highlight=False)
    log("\nWeak Unique Ciphers:\n", style="bold white", highlight=False)
    if weak_ciphers_global:
        sorted_weak_ciphers = sorted(weak_ciphers_global)
        if NUMBERING:
            for idx, cipher in enumerate(sorted_weak_ciphers, start=1):
                log(f"{idx}) {cipher}", style="red", highlight=False)
        else:
            for cipher in sorted_weak_ciphers:
                log(cipher, style="red", highlight=False)
    else:
        log("No weak ciphers detected.", style="green", highlight=False)
    weak_tls_domains = [host.hostname for host in hosts_info if domain_tls_weak.get(host.hostname)]
    log("\nDomains/IP with TLS versions below 1.2:\n", style="bold white", highlight=False)
    if weak_tls_domains:
        for domain in sorted(weak_tls_domains):
            log(f"{domain}", style="red", highlight=False)
    else:
        log("None", style="green", highlight=False)
    weak_cipher_domains = [host.hostname for host in hosts_info if domain_weak_ciphers.get(host.hostname)]
    log("\nDomains/IP with at least one weak cipher suite:\n", style="bold white", highlight=False)
    if weak_cipher_domains:
        for domain in sorted(weak_cipher_domains):
            log(f"{domain}", style="red", highlight=False)
    else:
        log("None", style="green", highlight=False)
    log("\nDomain-wise Weak TLS Versions, Weak Ciphers and Certificate Info:\n", style="bold white", highlight=False)
    for host in hosts_info:
        log(f"{host.hostname}:", style="bold white", highlight=False)
        tls_weak_list = sorted(domain_tls_weak.get(host.hostname, []))
        if tls_weak_list:
            log("  Weak TLS/SSL Versions:", style="bold white", highlight=False)
            if NUMBERING:
                for idx, tls in enumerate(tls_weak_list, start=1):
                    log(f"    {idx}) {tls}", style="red", highlight=False)
            else:
                for tls in tls_weak_list:
                    log(f"    {tls}", style="red", highlight=False)
        else:
            log("  No weak TLS/SSL versions detected.", style="green", highlight=False)
        if domain_weak_ciphers.get(host.hostname):
            log("  Weak Ciphers:", style="bold white", highlight=False)
            if NUMBERING:
                for idx, cipher in enumerate(sorted(set(domain_weak_ciphers[host.hostname])), start=1):
                    log(f"    {idx}) {cipher}", style="red", highlight=False)
            else:
                for cipher in sorted(set(domain_weak_ciphers[host.hostname])):
                    log(f"    {cipher}", style="red", highlight=False)
        else:
            log("  No weak ciphers detected.", style="green", highlight=False)
        if host.cert_cn:
            if is_ip_address(host.hostname) and not host.cert_cn.startswith("*."):
                try:
                    resolved_ip = socket.gethostbyname(host.cert_cn)
                    if resolved_ip == host.hostname:
                        log(f"  {host.hostname} - {host.cert_cn}", style="green", highlight=False)
                    else:
                        if certificate_matches_domain(host.cert_cn, host.hostname):
                            log(f"  Certificate issued to: {host.cert_cn}", style="green", highlight=False)
                        else:
                            log(f"  [!] Certificate subject mismatch: certificate is issued to '{host.cert_cn}'", style="red", highlight=False)
                except Exception:
                    if certificate_matches_domain(host.cert_cn, host.hostname):
                        log(f"  Certificate issued to: {host.cert_cn}", style="green", highlight=False)
                    else:
                        log(f"  [!] Certificate subject mismatch: certificate is issued to '{host.cert_cn}'", style="red", highlight=False)
            else:
                if certificate_matches_domain(host.cert_cn, host.hostname):
                    log(f"  Certificate issued to: {host.cert_cn}", style="green", highlight=False)
                else:
                    log(f"  [!] Certificate subject mismatch: certificate is issued to '{host.cert_cn}'", style="red", highlight=False)
        else:
            log("  No certificate information found.", style="red", highlight=False)
        log("", highlight=False)

def main() -> None:
    print_banner()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-d", "--domains", metavar="", type=str, help="File containing a list of domains/subnets/IPs (one per line).")
    group.add_argument("-x", "--xml", metavar="", type=str, help="nmap XML report file.")
    parser.add_argument("-p", "--ports", metavar="", type=str, default="443", help="Ports to scan (comma-separated or '-' for all ports).")
    parser.add_argument("-debug", "--debug", action="store_true", help="Enable debug output.")
    parser.add_argument("-n", "--number", action="store_true", help="Enable numbering of weak ciphers in the global report.")
    parser.add_argument("-s", "--save", metavar="", type=str, help="Save final report output to file.")
    parser.add_argument("-up", "--update", action="store_true", help="Update cipher cache from API")
    args = parser.parse_args()

    if not (args.domains or args.xml or args.update):
        parser.error("No input provided. Please specify a domain list (-d) or nmap XML file (-x), or use -up to update the cipher cache.")

    global DEBUG, NUMBERING
    DEBUG = args.debug
    NUMBERING = args.number
    
    if args.update:
        get_security_sets(update=True)
        if not (args.domains or args.xml):
            log("[*] Cipher cache updated successfully. Exiting.", style="green", highlight=False)
            sys.exit(0)
    
    try:
        if args.xml:
            log("[*] Using provided nmap XML report.", highlight=False)
            hosts_info = parse_nmap_output(os.path.abspath(args.xml))
        else:
            log("[*] Using domain list. Starting nmap scan...", highlight=False)
            domains_file = os.path.abspath(args.domains)
            targets = read_domains(domains_file)
            output_file = os.path.join(os.path.dirname(domains_file), "domains.xml")
            execute_nmap(targets, output_file, args.ports)
            hosts_info = parse_nmap_output(output_file)
        check_ciphers_with_api(hosts_info, args.update)
        if args.save:
            with open(args.save, "w", encoding="utf-8") as f:
                f.write("\n".join(report_lines))
            log(f"\n[*] Final report saved to {args.save}", style="green", highlight=False)
    except Exception as e:
        log(f"[!] Fatal error: {e}", style="red", highlight=False)
        sys.exit(1)

if __name__ == '__main__':
    main()
