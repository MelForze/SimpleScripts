#!/usr/bin/env python3

import argparse
import ipaddress
import os

def get_unique_subnets(input_list):
    """Get unique subnets from a list of IP addresses."""
    subnets = set()
    try:
        with open(input_list, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    # Attempt to parse the line as an IP address
                    ip = ipaddress.ip_address(line)
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    subnets.add(network)
                except ValueError:
                    # Attempt to parse the line as a network address
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        subnets.add(network)
                    except ValueError:
                        print(f"Invalid IP address or network: {line}")
    except FileNotFoundError:
        print(f"Error: Input file '{input_list}' not found.")
    except IOError as e:
        print(f"Error reading file '{input_list}': {e}")

    return sorted(subnets, key=lambda x: (x.network_address, x.prefixlen))

def save_to_file(output_file, subnets):
    """Save unique subnets to an output file."""
    try:
        with open(output_file, 'w') as file:
            for subnet in subnets:
                file.write(f"{subnet}\n")
        print(f"Unique subnets have been written to '{output_file}'")
    except IOError as e:
        print(f"Error writing to file '{output_file}': {e}")

def print_to_console(subnets):
    """Print unique subnets to the console."""
    print("Unique subnets:")
    for subnet in subnets:
        print(f"{subnet}")

def main(input_list, output_file=None):
    """Main function to process IPs and output unique subnets."""
    input_list = os.path.abspath(input_list)
    
    unique_subnets = get_unique_subnets(input_list)
    if not unique_subnets:
        print("No valid subnets were found.")
        return

    if output_file:
        save_to_file(output_file, unique_subnets)
    else:
        print_to_console(unique_subnets)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get unique subnets from a list of IP addresses.')
    parser.add_argument('-i', '--input', required=True, help='Input file with list of IP addresses')
    parser.add_argument('-o', '--output', help='(Optional) Output file to save unique subnets. If not specified, results are printed to the console.')

    args = parser.parse_args()
    main(args.input_list, args.output)