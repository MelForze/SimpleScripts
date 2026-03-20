#!/usr/bin/env python3
import argparse
import logging
import os
import xml.etree.ElementTree as ET


SUPPORTED_PROTOCOLS = ("tcp", "udp")
WEB_SERVICE_MARKERS = (
    "http",
    "https",
    "ssl/http",
    "ssl/https",
    "http-alt",
    "https-alt",
)
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443}

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def create_argument_parser(*args, **kwargs) -> argparse.ArgumentParser:
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def resolve_target(host: ET.Element) -> str | None:
    """Return the preferred target for a host: hostname, IPv4, IPv6, then any address."""
    ipv4_addrs: list[str] = []
    ipv6_addrs: list[str] = []
    other_addrs: list[str] = []
    hostname_value: str | None = None

    for address in host.findall("address"):
        addr = address.get("addr")
        addr_type = (address.get("addrtype") or "").lower()
        if not addr:
            continue
        if addr_type == "ipv4":
            ipv4_addrs.append(addr)
        elif addr_type == "ipv6":
            ipv6_addrs.append(addr)
        else:
            other_addrs.append(addr)

    for hostname in host.findall("./hostnames/hostname"):
        name = hostname.get("name")
        if name:
            hostname_value = name
            break

    if hostname_value:
        return hostname_value
    if ipv4_addrs:
        return ipv4_addrs[0]
    if ipv6_addrs:
        return ipv6_addrs[0]
    if other_addrs:
        return other_addrs[0]
    return None


def parse_port_spec(port_spec: str | None) -> list[int] | None:
    """Parse a strict port specification and return sorted unique ports."""
    if not port_spec:
        return None

    ports: set[int] = set()
    invalid_tokens: list[str] = []

    for raw_part in port_spec.split(","):
        part = raw_part.strip()
        if not part:
            continue

        if "-" in part:
            pieces = [piece.strip() for piece in part.split("-", 1)]
            if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
                invalid_tokens.append(part)
                continue
            start, end = (int(piece) for piece in pieces)
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                invalid_tokens.append(part)
                continue
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
            continue

        if not part.isdigit():
            invalid_tokens.append(part)
            continue

        port = int(part)
        if not 1 <= port <= 65535:
            invalid_tokens.append(part)
            continue
        ports.add(port)

    if invalid_tokens:
        invalid_text = ", ".join(invalid_tokens)
        raise ValueError(
            f"Invalid port specification value(s): {invalid_text}. "
            "Use formats like 80, 443, 22-25, or 80,443,8080-8090."
        )

    return sorted(ports) if ports else None


def parse_protocols(protocol_str: str | None) -> list[str]:
    """Parse a strict protocol specification and return unique ordered values."""
    if not protocol_str:
        return ["tcp"]

    protocols: list[str] = []
    invalid_values: list[str] = []

    for raw_proto in protocol_str.split(","):
        proto = raw_proto.strip().lower()
        if not proto:
            continue
        if proto not in SUPPORTED_PROTOCOLS:
            invalid_values.append(proto)
            continue
        if proto not in protocols:
            protocols.append(proto)

    if invalid_values:
        invalid_text = ", ".join(invalid_values)
        raise ValueError(
            f"Unsupported protocol value(s): {invalid_text}. Allowed values: tcp, udp."
        )

    return protocols or ["tcp"]


def is_web_like(service_raw: str, port: int) -> bool:
    """Return True when the service/port pair looks like a web endpoint."""
    return any(marker in service_raw for marker in WEB_SERVICE_MARKERS) or port in WEB_PORTS


def parse_nmap_xml(
    xml_file: str,
    target_ports: list[int] | None = None,
    protocols: list[str] | None = None,
    web_only: bool = False,
) -> list[dict[str, object]]:
    """Parse an Nmap XML file and return per-host records."""
    effective_protocols = protocols or ["tcp"]
    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts_info: list[dict[str, object]] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        target = resolve_target(host)
        if not target:
            continue

        addresses = [
            addr.get("addr")
            for addr in host.findall("address")
            if addr.get("addrtype") in {"ipv4", "ipv6"} and addr.get("addr")
        ]
        hostnames = [
            hostname.get("name")
            for hostname in host.findall("hostnames/hostname")
            if hostname.get("name")
        ]

        ports = host.find("ports")
        if ports is None:
            continue

        host_ports: list[dict[str, object]] = []

        for port in ports.findall("port"):
            port_id = port.get("portid")
            port_protocol = (port.get("protocol") or "").lower()

            if not port_id or not port_id.isdigit():
                continue
            if port_protocol not in effective_protocols:
                continue

            port_number = int(port_id)
            if target_ports and port_number not in target_ports:
                continue

            state = port.find("state")
            state_str = state.get("state") if state is not None else "unknown"

            service = port.find("service")
            service_name = "unknown"
            service_product = ""
            service_version = ""
            service_raw = "unknown"

            if service is not None:
                service_raw = (service.get("name") or "unknown").lower()
                service_name = service.get("name", "unknown")
                service_product = service.get("product", "")
                service_version = service.get("version", "")

                if service_product and service_version:
                    service_name = f"{service_name} ({service_product} {service_version})"
                elif service_product:
                    service_name = f"{service_name} ({service_product})"
                elif service_version:
                    service_name = f"{service_name} (version: {service_version})"

            if web_only and not is_web_like(service_raw, port_number):
                continue

            if target_ports and state_str != "open":
                continue

            host_ports.append(
                {
                    "port": port_number,
                    "protocol": port_protocol,
                    "state": state_str,
                    "service": service_name,
                    "service_raw": service_raw,
                    "port_str": f"{port_number}/{port_protocol}",
                }
            )

        if not host_ports:
            continue

        host_ports.sort(key=lambda item: (int(item["port"]), str(item["protocol"])))
        hosts_info.append(
            {
                "target": target,
                "addresses": addresses,
                "hostnames": hostnames,
                "ports": host_ports,
            }
        )

    hosts_info.sort(key=lambda item: str(item["target"]))
    return hosts_info


def export_to_file(hosts_info: list[dict[str, object]], output_file: str) -> tuple[bool, int]:
    """Write host lines in the format target [port1, port2] to a file."""
    lines_to_write: list[str] = []

    for host in hosts_info:
        target = str(host.get("target", "")).strip()
        if not target:
            continue

        open_ports = [
            str(port_info["port"])
            for port_info in host.get("ports", [])
            if port_info.get("state") == "open"
        ]

        if open_ports:
            lines_to_write.append(f"{target} [{', '.join(open_ports)}]")

    if not lines_to_write:
        logging.warning("No data available to write to the export file.")
        return False, 0

    try:
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_file, "w", encoding="utf-8") as file_handle:
            for line in lines_to_write:
                file_handle.write(line + "\n")

        return True, len(lines_to_write)
    except OSError as exc:
        logging.error("Failed to write export file '%s': %s", output_file, exc)
        return False, 0


def build_open_port_map(hosts_info: list[dict[str, object]]) -> dict[str, list[int]]:
    """Return a mapping of target to sorted open port numbers."""
    host_port_map: dict[str, list[int]] = {}

    for host in hosts_info:
        target = str(host["target"])
        open_ports = [
            int(port_info["port"])
            for port_info in host.get("ports", [])
            if port_info.get("state") == "open"
        ]
        if not open_ports:
            continue
        host_port_map[target] = sorted(set(open_ports))

    return host_port_map


def main(argv: list[str] | None = None) -> int:
    parser = create_argument_parser(
        description="Analyze Nmap XML reports.",
        epilog=(
            "Examples:\n"
            "  nmap_to_analyze.py -i scan.xml\n"
            "  nmap_to_analyze.py -i scan.xml -p 80,443 --protocol tcp\n"
            "  nmap_to_analyze.py -i scan.xml --web-only --list-ports\n"
            "  nmap_to_analyze.py -i scan.xml -e hosts.txt"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        metavar="FILE",
        help="Path to the Nmap XML input file.",
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="PORTS",
        help="Filter hosts by port values such as 80, 443, 22-25, or 80,443,8080-8090.",
    )
    parser.add_argument(
        "--protocol",
        default="tcp",
        metavar="PROTOCOLS",
        help="Comma-separated protocols to include: tcp, udp, or tcp,udp. Default: tcp.",
    )
    parser.add_argument(
        "--web-only",
        "--https-only",
        dest="web_only",
        action="store_true",
        help="Keep only web-like ports using HTTP/HTTPS service and port heuristics.",
    )
    parser.add_argument(
        "-o",
        "--open-only",
        action="store_true",
        help="Show only open ports in the summary table output.",
    )
    parser.add_argument(
        "--list-ports",
        action="store_true",
        help="Print one line per host in the format target [port1, port2, ...].",
    )
    parser.add_argument(
        "-e",
        "--export",
        metavar="FILE",
        help="Write target [ports] lines to a file and suppress normal output.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed per-host output for port-filtered searches.",
    )

    args = parser.parse_args(argv)

    if not os.path.isfile(args.input):
        logging.error("Input file '%s' not found.", args.input)
        return 1

    try:
        protocols = parse_protocols(args.protocol)
        target_ports = parse_port_spec(args.port) if args.port else None
        hosts_info = parse_nmap_xml(
            args.input,
            target_ports=target_ports,
            protocols=protocols,
            web_only=args.web_only,
        )
    except ValueError as exc:
        logging.error("%s", exc)
        return 1
    except ET.ParseError as exc:
        logging.error("Failed to parse XML '%s': %s", args.input, exc)
        return 1
    except FileNotFoundError:
        logging.error("Input file '%s' not found.", args.input)
        return 1
    except OSError as exc:
        logging.error("Failed to read '%s': %s", args.input, exc)
        return 1

    if not hosts_info:
        if args.export:
            logging.warning("No matching data found to export.")
        else:
            logging.warning("No matching data found.")
        return 2

    if args.export:
        success, count = export_to_file(hosts_info, args.export)
        if not success:
            return 1
        print(f"Exported {count} record(s) to: {args.export}")
        return 0

    if args.list_ports:
        host_port_map = build_open_port_map(hosts_info)
        if not host_port_map:
            logging.warning("No open ports matched the selected filters.")
            return 2

        for target, ports in host_port_map.items():
            port_values = ", ".join(str(port) for port in ports)
            print(f"{target} [{port_values}]")

        print(f"Hosts found: {len(host_port_map)}")
        return 0

    if target_ports:
        protocol_display = ",".join(protocols)
        port_display = ", ".join(str(port) for port in target_ports)
        if len(target_ports) == 1:
            print(f"Hosts with open port {target_ports[0]}/{protocol_display}:")
        else:
            print(f"Hosts with open ports {port_display}/{protocol_display}:")
        print("-" * 60)

        for host in hosts_info:
            target = str(host["target"])
            addresses = ", ".join(host.get("addresses", [])) or "N/A"
            hostnames = ", ".join(host.get("hostnames", [])) or "N/A"
            ports = host.get("ports", [])

            if args.verbose:
                print(f"Target: {target}")
                if hostnames != "N/A":
                    print(f"  Hostname(s): {hostnames}")
                print(f"  IP address(es): {addresses}")
                print("  Open ports:")
                for port_info in ports:
                    print(
                        f"    - {port_info['port_str']}: "
                        f"{port_info['service']} ({port_info['state']})"
                    )
                print("-" * 60)
                continue

            port_values = [str(port_info["port"]) for port_info in ports]
            if len(target_ports) == 1:
                print(target)
            elif len(port_values) == 1:
                print(f"{target}:{port_values[0]}")
            else:
                print(f"{target}: {', '.join(port_values)}")
        return 0

    all_ports: list[dict[str, object]] = []
    seen_ports: set[str] = set()

    for host in hosts_info:
        for port_info in host.get("ports", []):
            if args.open_only and port_info.get("state") != "open":
                continue

            port_key = str(port_info["port_str"])
            if port_key in seen_ports:
                continue
            seen_ports.add(port_key)
            all_ports.append(port_info)

    if not all_ports:
        logging.warning("No ports matched the selected filters.")
        return 2

    all_ports.sort(key=lambda item: (int(item["port"]), str(item["protocol"])))

    if args.web_only:
        print("Web-like ports:")
    else:
        print(f"Unique ports: {len(all_ports)}")

    print(f"{'Port':<10} {'State':<10} {'Service':<30}")
    print("-" * 50)
    for port_info in all_ports:
        print(
            f"{port_info['port_str']:<10} "
            f"{port_info['state']:<10} "
            f"{port_info['service']:<30}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
