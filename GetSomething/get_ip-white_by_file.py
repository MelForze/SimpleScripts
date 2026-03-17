#!/usr/bin/env python3

import argparse
import ipaddress
import os


MAX_EXPANDABLE_ADDRESSES = 4096


def is_public_ip(ip):
    """Check whether the given address is globally routable."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global and not ip_obj.is_multicast
    except ValueError:
        return False


def iter_network_hosts(network):
    """Iterate host addresses without including IPv4 network/broadcast."""
    if isinstance(network, ipaddress.IPv4Network):
        return network.hosts()
    return iter(network)


def process_line_as_network(line):
    """Process a network and return globally routable host addresses."""
    try:
        network = ipaddress.ip_network(line, strict=False)
    except ValueError:
        return f"Invalid IP address or network format: {line}"

    if network.num_addresses > MAX_EXPANDABLE_ADDRESSES:
        return (
            f"Skipping large subnet {network}: {network.num_addresses} addresses exceed "
            f"the safety limit ({MAX_EXPANDABLE_ADDRESSES})."
        )

    public_ips = [str(ip) for ip in iter_network_hosts(network) if is_public_ip(ip)]
    if public_ips:
        return public_ips

    return f"No public IP addresses in subnet {line}"


def sort_ip_strings(ips):
    return sorted(
        set(ips),
        key=lambda value: (
            ipaddress.ip_address(value).version,
            int(ipaddress.ip_address(value)),
        ),
    )


def find_public_ips(input_file):
    """Find all globally routable IP addresses from the input file."""
    public_ips = []
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                if is_public_ip(line):
                    public_ips.append(str(ipaddress.ip_address(line)))
                    continue

                result = process_line_as_network(line)
                if isinstance(result, list):
                    public_ips.extend(result)
                else:
                    print(result)
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
    except IOError as exc:
        print(f"Error reading file '{input_file}': {exc}")

    return sort_ip_strings(public_ips)


def print_to_console(ips):
    """Print IPs to the console."""
    if ips:
        print("Public IP addresses:")
        for ip in ips:
            print(ip)


def save_to_file(output_file, ips):
    """Save the public IP addresses to a file."""
    try:
        with open(output_file, "w", encoding="utf-8") as file:
            for ip in ips:
                file.write(f"{ip}\n")
        print(f"Public IP addresses have been written to '{output_file}'")
    except IOError as exc:
        print(f"Error writing to file '{output_file}': {exc}")


def main(input_file, output_file=None):
    """Main function to process input file and manage output."""
    input_file = os.path.abspath(input_file)

    public_ips = find_public_ips(input_file)
    if not public_ips:
        print("No public IP addresses were found.")
        return

    if output_file:
        save_to_file(output_file, public_ips)
    else:
        print_to_console(public_ips)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Extract public IP addresses from a file, including expanding "
            "small subnets into host IPs."
        )
    )
    parser.add_argument("-i", "--input", required=True, help="Input file with IP addresses or networks")
    parser.add_argument(
        "-o",
        "--output",
        help="(Optional) Output file to save public IP addresses. If not specified, results are printed to the console.",
    )

    args = parser.parse_args()
    main(args.input, args.output)
