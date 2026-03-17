#!/usr/bin/env python3

import argparse
import ipaddress
import os
import re


CANDIDATE_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


def normalize_candidate(candidate):
    if "/" in candidate:
        try:
            return str(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def extract_ips(input_text):
    """Extract valid IPv4 addresses and subnets from the input text."""
    found = []
    for candidate in CANDIDATE_PATTERN.findall(input_text):
        normalized = normalize_candidate(candidate)
        if normalized is not None:
            found.append(normalized)
    return found


def sort_key(value):
    if "/" in value:
        network = ipaddress.ip_network(value, strict=False)
        return (1, network.version, int(network.network_address), network.prefixlen)

    address = ipaddress.ip_address(value)
    return (0, address.version, int(address), address.max_prefixlen)


def unique_ips(input_ips):
    """Remove duplicates and sort the list of IPs and subnets."""
    return sorted(set(input_ips), key=sort_key)


def save_to_file(output_file, data):
    """Write data to the specified output file."""
    output_file = os.path.abspath(output_file)
    try:
        with open(output_file, "w", encoding="utf-8") as file:
            for item in data:
                file.write(f"{item}\n")
        print(f"Unique IP addresses and subnets have been written to '{output_file}'")
    except IOError as exc:
        print(f"Error writing to file '{output_file}': {exc}")


def print_to_console(data):
    """Print data to the console."""
    print("Unique IP addresses and subnets:")
    for item in data:
        print(item)


def main(input_file, output_file=None):
    """Main function to process IPs from an input file and save or print them."""
    input_file = os.path.abspath(input_file)
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            content = file.read()

        all_ips = extract_ips(content)
        unique_ips_list = unique_ips(all_ips)

        if not unique_ips_list:
            print("No IP addresses or subnets found in the input file.")
            return

        if output_file:
            save_to_file(output_file, unique_ips_list)
        else:
            print_to_console(unique_ips_list)
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
    except IOError as exc:
        print(f"Error reading file '{input_file}': {exc}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract unique IPv4 addresses and subnets from a file."
    )
    parser.add_argument("-i", "--input", required=True, help="Input file path containing the data.")
    parser.add_argument(
        "-o",
        "--output",
        help="(Optional) Output file path to save unique IP addresses and subnets. If not specified, results are printed to the console.",
    )

    args = parser.parse_args()
    main(args.input, args.output)
