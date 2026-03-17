#!/usr/bin/env python3

import argparse
import ipaddress
import os


DEFAULT_PREFIXLEN = {
    4: 24,
    6: 64,
}


def parse_ip_or_network(line: str):
    """
    Interpret a line as either:
    1) a single IP address, mapped to a default subnet size
    2) a CIDR network
    """
    line = line.strip()
    if not line:
        return None

    try:
        ip = ipaddress.ip_address(line)
        prefixlen = DEFAULT_PREFIXLEN[ip.version]
        return ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
    except ValueError:
        pass

    try:
        return ipaddress.ip_network(line, strict=False)
    except ValueError:
        print(f"Invalid IP address or network: {line}")
        return None


def subnet_sort_key(network):
    return (network.version, int(network.network_address), network.prefixlen)


def get_unique_subnets(input_file: str):
    """Return a sorted list of unique subnets from the input file."""
    subnets = set()
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            for line in file:
                network = parse_ip_or_network(line)
                if network:
                    subnets.add(network)
    except OSError as exc:
        print(f"Error reading file '{input_file}': {exc}")
        return []

    return sorted(subnets, key=subnet_sort_key)


def save_to_file(output_file: str, subnets):
    """Save the subnet list to a file."""
    try:
        with open(output_file, "w", encoding="utf-8") as file:
            for subnet in subnets:
                file.write(f"{subnet}\n")
        print(f"Unique subnets have been written to '{output_file}'")
    except OSError as exc:
        print(f"Error writing to file '{output_file}': {exc}")


def print_to_console(subnets):
    """Print the subnet list to the console."""
    print("Unique subnets:")
    for subnet in subnets:
        print(subnet)


def main(input_file: str, output_file: str = None):
    """Main function."""
    input_file = os.path.abspath(input_file)

    unique_subnets = get_unique_subnets(input_file)
    if not unique_subnets:
        print("No valid subnets were found.")
        return

    if output_file:
        save_to_file(output_file, unique_subnets)
    else:
        print_to_console(unique_subnets)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Get unique subnets from a list of IP addresses."
    )
    parser.add_argument("-i", "--input", required=True, help="Input file with list of IP addresses")
    parser.add_argument(
        "-o",
        "--output",
        help="(Optional) Output file to save unique subnets. If not specified, results are printed to the console.",
    )

    args = parser.parse_args()
    main(args.input, args.output)
