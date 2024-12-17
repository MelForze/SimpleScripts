#!/usr/bin/env python3

import argparse
import ipaddress
import os

def is_public_ip(ip):
    """Check if the given IP address is public."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False

def process_line_as_network(line):
    """Process a line as a network and extract public IPs."""
    try:
        network = ipaddress.ip_network(line, strict=False)
        public_ips = [str(ip) for ip in network if is_public_ip(ip)]
        if public_ips:
            return public_ips
        else:
            return f"No public IP addresses in subnet {line}"
    except ValueError:
        return f"Invalid IP address or network format: {line}"

def find_public_ips(input_file):
    """Find all public IP addresses from the input file."""
    public_ips = []
    try:
        with open(input_file, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                if is_public_ip(line):
                    public_ips.append(line)
                else:
                    result = process_line_as_network(line)
                    if isinstance(result, list):
                        public_ips.extend(result)
                    else:
                        print(result)  # Output the message for handling issues
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
    except IOError as e:
        print(f"Error reading file '{input_file}': {e}")

    return sorted(set(public_ips))

def print_to_console(ips):
    """Print IPs to the console."""
    if ips:
        print("Public IP addresses:")
        for ip in ips:
            print(ip)

def save_to_file(output_file, ips):
    """Save the public IP addresses to a file."""
    try:
        with open(output_file, 'w') as file:
            for ip in ips:
                file.write(f"{ip}\n")
        print(f"Public IP addresses have been written to '{output_file}'")
    except IOError as e:
        print(f"Error writing to file '{output_file}': {e}")

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
    parser = argparse.ArgumentParser(description='Extract public IP addresses from a file, including expanding subnets into IPs.')
    parser.add_argument('-i', '--input', required=True, help='Input file with IP addresses or networks')
    parser.add_argument('-o', '--output', help='(Optional) Output file to save public IP addresses. If not specified, results are printed to the console.')

    args = parser.parse_args()
    main(args.input, args.output)