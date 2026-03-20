#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Set


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)

def build_console():
    try:
        from rich.console import Console
    except ModuleNotFoundError:
        class Console:  # type: ignore[no-redef]
            def print(self, *args, **kwargs):
                print(*args)

    return Console()


def load_requests():
    try:
        import requests as requests_module
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Missing dependency: install 'requests' to use CiphersHunter."
        ) from exc
    return requests_module

DEBUG = False
NUMBERING = False
console = build_console()
report_lines: List[str] = []

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CIPHER_CACHE_PATH = os.path.join(SCRIPT_DIR, "ciphers_cache.json")
MARKUP_TAG_RE = re.compile(r"\[(?:/?[A-Za-z][^\]]*)\]")
SECURITY_LEVELS = ("insecure", "weak", "secure", "recommended")

def log(msg: str, style: str = None, highlight: bool = False) -> None:
    plain = MARKUP_TAG_RE.sub("", msg).replace("[!]", "!")
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
    cert_names: List[str] = field(default_factory=list)

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
    description = (
        "Scans domains for SSL/TLS cipher security using nmap and a local "
        "ciphers_cache.json file. Use -up only when you want to refresh the "
        "local cipher cache from the network.\n"
    )
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

def execute_nmap(domains: List[str], output_path: str, ports: str) -> int:
    log("[*] Running nmap on the following targets:", highlight=False)
    log("    " + ", ".join(domains), highlight=False)
    nmap_command = ["nmap","-Pn", "-sV", "--script", "ssl-enum-ciphers,ssl-cert", "-p", ports, "-oX", output_path] + domains
    try:
        result = subprocess.run(
            nmap_command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        log("[!] Error: nmap is not installed or not found in PATH.", style="red", highlight=False)
        return 1
    except OSError as exc:
        log(f"[!] Error running nmap: {exc}", style="red", highlight=False)
        return 1
    if result.returncode != 0:
        log(
            f"[!] Error: nmap exited with code {result.returncode}. Error: {result.stderr.strip()}",
            style="red",
            highlight=False,
        )
        return 1
    log("[*] nmap completed successfully.", highlight=False)
    return 0

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

def normalize_hostname(value: str) -> str:
    return value.strip().rstrip(".").lower()

def _match_single_certificate_name(cert_name: str, domain: str) -> bool:
    cert_name = normalize_hostname(cert_name)
    domain = normalize_hostname(domain)

    if not cert_name or not domain:
        return False
    if is_ip_address(domain):
        return cert_name == domain

    if cert_name.startswith("*."):
        base = cert_name[2:]
        if not base:
            return False

        domain_labels = domain.split(".")
        base_labels = base.split(".")
        return len(domain_labels) == len(base_labels) + 1 and domain_labels[1:] == base_labels

    return cert_name == domain


def _normalize_certificate_names(cert_names: str | List[str]) -> List[str]:
    if isinstance(cert_names, str):
        return [cert_names] if cert_names else []
    return [name for name in cert_names if name]


def find_matching_certificate_name(cert_names: str | List[str], domain: str) -> str | None:
    names = _normalize_certificate_names(cert_names)
    for name in names:
        if _match_single_certificate_name(name, domain):
            return name

    if is_ip_address(domain):
        for name in names:
            normalized_name = normalize_hostname(name)
            if not normalized_name or is_ip_address(normalized_name) or normalized_name.startswith("*."):
                continue
            try:
                resolved_ip = socket.gethostbyname(normalized_name)
            except Exception:
                continue
            if resolved_ip == domain:
                return name
    return None


def certificate_matches_domain(cert_names: str | List[str], domain: str) -> bool:
    return find_matching_certificate_name(cert_names, domain) is not None


def _deduplicate_preserve_order(values: List[str]) -> List[str]:
    return list(dict.fromkeys(values))


def _extract_common_name(ssl_cert_script) -> str:
    subject_table = ssl_cert_script.find("table[@key='subject']")
    if subject_table is None:
        return ""
    common_name_elem = subject_table.find("elem[@key='commonName']")
    if common_name_elem is None or not common_name_elem.text:
        return ""
    return common_name_elem.text.strip()


def _looks_like_san_table(table) -> bool:
    key = (table.attrib.get("key") or "").strip().lower()
    return "subjectaltname" in key or "subject alternative name" in key


def _extract_names_from_san_text(value: str) -> List[str]:
    names: List[str] = []
    for raw_token in re.split(r"[\n,]", value):
        token = raw_token.strip()
        if not token:
            continue
        lowered = token.lower()
        if lowered.startswith("dns:"):
            names.append(token.split(":", 1)[1].strip())
        elif lowered.startswith("ip address:"):
            names.append(token.split(":", 1)[1].strip())
        elif lowered.startswith("ip:"):
            names.append(token.split(":", 1)[1].strip())
        else:
            names.append(token)
    return names


def _extract_subject_alt_names(ssl_cert_script) -> List[str]:
    alt_names: List[str] = []
    for table in ssl_cert_script.iter("table"):
        if not _looks_like_san_table(table):
            continue
        table_key = (table.attrib.get("key") or "").strip()
        if table_key and not _looks_like_san_table(table):
            alt_names.append(table_key)
        for elem in table.iter("elem"):
            if elem.text:
                alt_names.extend(_extract_names_from_san_text(elem.text))
            elem_key = (elem.attrib.get("key") or "").strip()
            if elem_key and elem.text and elem_key.lower() not in {"commonname"}:
                alt_names.append(f"{elem_key}:{elem.text.strip()}")

    cleaned_names: List[str] = []
    for name in alt_names:
        cleaned_names.extend(_extract_names_from_san_text(name))
    return _deduplicate_preserve_order([name for name in cleaned_names if name])


def extract_certificate_names(ssl_cert_script) -> tuple[str, List[str]]:
    cert_cn = _extract_common_name(ssl_cert_script)
    cert_names: List[str] = []
    if cert_cn:
        cert_names.append(cert_cn)
    cert_names.extend(_extract_subject_alt_names(ssl_cert_script))
    return cert_cn, _deduplicate_preserve_order(cert_names)

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
        cert_names: List[str] = []
        for port in host.findall('ports/port'):
            ssl_cert_script = port.find("script[@id='ssl-cert']")
            if ssl_cert_script is not None:
                cert_cn, cert_names = extract_certificate_names(ssl_cert_script)
                if cert_cn or cert_names:
                    break
        hosts_info.append(
            HostCipherInfo(
                hostname=hostname,
                ciphers=ciphers,
                tls_versions=tls_versions,
                cert_cn=cert_cn,
                cert_names=cert_names,
            )
        )
    if not hosts_info:
        log("[!] Warning: no hosts found in the XML output.", style="red", highlight=False)
    return hosts_info

def _normalize_security_sets(data: dict) -> dict:
    if not isinstance(data, dict):
        raise RuntimeError("Cipher cache is invalid: expected a JSON object at the top level.")

    normalized = {}
    for level in SECURITY_LEVELS:
        values = data.get(level)
        if not isinstance(values, list):
            raise RuntimeError(
                f"Cipher cache is invalid: expected a list for '{level}'."
            )
        normalized[level] = {str(value) for value in values if value}
    return normalized


def load_cached_security_sets(cache_path: str | None = None) -> dict:
    cache_path = cache_path or CIPHER_CACHE_PATH
    try:
        with open(cache_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Cipher cache file '{cache_path}' was not found. Run CiphersHunter.py -up to create/update it."
        ) from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Cipher cache file '{cache_path}' is invalid JSON: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not read cipher cache file '{cache_path}': {exc}") from exc

    return _normalize_security_sets(data)


def fetch_security_sets_from_api() -> dict:
    base_url = "https://ciphersuite.info/api"
    security_sets = {}
    requests_module = load_requests()
    for level in SECURITY_LEVELS:
        url = f"{base_url}/cs/security/{level}"
        ciphers_set = set()
        try:
            if DEBUG:
                log(f"[*] Querying API for level '{level}' via URL: {url}", style="green", highlight=False)
            response = requests_module.get(url, timeout=10)
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
    return security_sets


def save_security_sets(security_sets: dict, cache_path: str | None = None) -> None:
    cache_path = cache_path or CIPHER_CACHE_PATH
    try:
        with open(cache_path, "w", encoding="utf-8") as handle:
            out_data = {level: sorted(security_sets.get(level, set())) for level in SECURITY_LEVELS}
            json.dump(out_data, handle, ensure_ascii=False, indent=2)
    except OSError as exc:
        raise RuntimeError(f"Could not write cipher cache file '{cache_path}': {exc}") from exc


def update_cipher_cache(cache_path: str | None = None) -> dict:
    cache_path = cache_path or CIPHER_CACHE_PATH
    security_sets = fetch_security_sets_from_api()
    save_security_sets(security_sets, cache_path=cache_path)
    log(f"[*] Cipher cache saved to {cache_path}", style="green", highlight=False)
    return security_sets


def get_security_sets() -> dict:
    security_sets = load_cached_security_sets()
    log(f"[*] Cipher cache loaded from {CIPHER_CACHE_PATH}", style="green", highlight=False)
    return security_sets

def classify_cipher_security(cipher: str, security_sets: dict) -> str:
    if cipher in security_sets.get("insecure", set()) or cipher in security_sets.get("weak", set()):
        return "weak"
    if cipher in security_sets.get("secure", set()) or cipher in security_sets.get("recommended", set()):
        return "safe"
    return "unknown"

def is_cipher_safe(cipher: str, security_sets: dict) -> bool:
    return classify_cipher_security(cipher, security_sets) == "safe"

def check_ciphers_with_api(hosts_info: List[HostCipherInfo], update: bool = False) -> None:
    security_sets = get_security_sets()
    weak_ciphers_global = set()
    unknown_ciphers_global = set()
    domain_weak_ciphers = {}
    domain_unknown_ciphers = {}
    domain_tls_weak = {}
    global_tls_versions = set()
    for host in hosts_info:
        global_tls_versions |= host.tls_versions
        weak_tls_for_domain = {tls for tls in host.tls_versions if tls not in {"TLSv1.2", "TLSv1.3"}}
        domain_tls_weak[host.hostname] = weak_tls_for_domain
        weak_for_domain = []
        unknown_for_domain = []
        if not host.ciphers:
            domain_weak_ciphers[host.hostname] = weak_for_domain
            domain_unknown_ciphers[host.hostname] = unknown_for_domain
        else:
            log(f"[*] Processing target: [bold white]{host.hostname}[/bold white]", highlight=False)
            for cipher in host.ciphers:
                classification = classify_cipher_security(cipher, security_sets)
                if DEBUG:
                    style = "green" if classification == "safe" else "red" if classification == "weak" else "yellow"
                    log(
                        f"    [DEBUG] Cipher '{cipher}' classified as {classification}.",
                        style=style,
                        highlight=False,
                    )
                if classification == "weak":
                    weak_for_domain.append(cipher)
                    weak_ciphers_global.add(cipher)
                elif classification == "unknown":
                    unknown_for_domain.append(cipher)
                    unknown_ciphers_global.add(cipher)
            domain_weak_ciphers[host.hostname] = weak_for_domain
            domain_unknown_ciphers[host.hostname] = unknown_for_domain

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
    log("\nUnknown/Unclassified Ciphers:\n", style="bold white", highlight=False)
    if unknown_ciphers_global:
        for cipher in sorted(unknown_ciphers_global):
            log(cipher, style="yellow", highlight=False)
    else:
        log("No unknown ciphers detected.", style="green", highlight=False)
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
    unknown_cipher_domains = [host.hostname for host in hosts_info if domain_unknown_ciphers.get(host.hostname)]
    log("\nDomains/IP with unknown or unclassified cipher suites:\n", style="bold white", highlight=False)
    if unknown_cipher_domains:
        for domain in sorted(unknown_cipher_domains):
            log(f"{domain}", style="yellow", highlight=False)
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
        if domain_unknown_ciphers.get(host.hostname):
            log("  Unknown/Unclassified Ciphers:", style="bold white", highlight=False)
            for cipher in sorted(set(domain_unknown_ciphers[host.hostname])):
                log(f"    {cipher}", style="yellow", highlight=False)
        else:
            log("  No unknown ciphers detected.", style="green", highlight=False)
        cert_names = host.cert_names or ([host.cert_cn] if host.cert_cn else [])
        if cert_names:
            matching_name = find_matching_certificate_name(cert_names, host.hostname)
            cert_names_display = ", ".join(cert_names)
            if matching_name:
                log(f"  Certificate issued to: {matching_name}", style="green", highlight=False)
                if len(cert_names) > 1:
                    log(f"  Certificate names: {cert_names_display}", style="green", highlight=False)
            else:
                log(
                    f"  [!] Certificate subject mismatch: certificate names are '{cert_names_display}'",
                    style="red",
                    highlight=False,
                )
        else:
            log("  No certificate information found.", style="red", highlight=False)
        log("", highlight=False)

def main(argv: list[str] | None = None) -> int:
    report_lines.clear()
    print_banner()
    parser = create_argument_parser()
    parser.add_argument("-debug", "--debug", action="store_true", help="Enable debug output.")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-d", "--domains", metavar="", type=str, help="File containing a list of domains/subnets/IPs (one per line).")
    group.add_argument("-x", "--xml", metavar="", type=str, help="nmap XML report file.")
    parser.add_argument(
        "-p",
        "--port",
        "--ports",
        dest="ports",
        metavar="",
        type=str,
        default="443",
        help="Ports to scan (comma-separated or '-' for all ports). Default: 443.",
    )
    parser.add_argument("-n", "--number", action="store_true", help="Enable numbering of weak ciphers in the global report.")
    parser.add_argument("-s", "--save", metavar="", type=str, help="Save final report output to file.")
    parser.add_argument("-up", "--update", action="store_true", help="Update cipher cache from API")
    args = parser.parse_args(argv)

    if not (args.domains or args.xml or args.update):
        print(
            "Error: no input provided. Specify a domain list (-d), an nmap XML file (-x), or use -up to update the cipher cache.",
            file=sys.stderr,
        )
        return 1

    global DEBUG, NUMBERING
    DEBUG = args.debug
    NUMBERING = args.number
    
    if args.update:
        try:
            update_cipher_cache()
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        if not (args.domains or args.xml):
            log("[*] Cipher cache updated successfully. Exiting.", style="green", highlight=False)
            return 0
    
    try:
        if args.xml:
            log("[*] Using provided nmap XML report.", highlight=False)
            hosts_info = parse_nmap_output(os.path.abspath(args.xml))
        else:
            log("[*] Using domain list. Starting nmap scan...", highlight=False)
            domains_file = os.path.abspath(args.domains)
            targets = read_domains(domains_file)
            output_file = os.path.join(os.path.dirname(domains_file), "domains.xml")
            if execute_nmap(targets, output_file, args.ports) != 0:
                return 1
            hosts_info = parse_nmap_output(output_file)
        check_ciphers_with_api(hosts_info, args.update)
        if args.save:
            with open(args.save, "w", encoding="utf-8") as f:
                f.write("\n".join(report_lines))
            log(f"\n[*] Final report saved to {args.save}", style="green", highlight=False)
        return 0
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as e:
        log(f"[!] Fatal error: {e}", style="red", highlight=False)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
