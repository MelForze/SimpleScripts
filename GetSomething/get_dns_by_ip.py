#!/usr/bin/env python3

import socket
import argparse
import os

def get_dns_name(ip_address):
    """Get the DNS name for a given IP address."""
    try:
        dns_name, _, _ = socket.gethostbyaddr(ip_address)
        return dns_name
    except (socket.herror, socket.gaierror):
        return "DNS unreachable"

def process_ip(ip_address, output_file=None):
    """Process a single IP address, resolving it to a DNS name."""
    dns_name = get_dns_name(ip_address)
    result_line = f"{ip_address} - {dns_name}"
    
    if output_file:
        output_file = os.path.abspath(output_file)
        try:
            with open(output_file, 'w') as outfile:
                outfile.write(result_line + "\n")
        except IOError as e:
            print(f"Error writing to file '{output_file}': {e}")
    else:
        print(result_line)

def process_ip_file(input_file, output_file=None):
    """Process a file of IP addresses, resolving each to a DNS name."""
    input_file = os.path.abspath(input_file)
    try:
        with open(input_file, 'r') as infile:
            results = []
            for line in infile:
                ip_address = line.strip()
                if ip_address:
                    dns_name = get_dns_name(ip_address)
                    result_line = f"{ip_address} - {dns_name}"
                    results.append(result_line)
            
            if output_file:
                output_file = os.path.abspath(output_file)
                with open(output_file, 'w') as outfile:
                    for result_line in results:
                        outfile.write(result_line + "\n")
            else:
                for result_line in results:
                    print(result_line)
                    
    except FileNotFoundError:
        print(f"Input file '{input_file}' not found.")
    except IOError as e:
        print(f"Error processing files: {e}")

def main(ip_address=None, input_file=None, output_file=None):
    """Main function to process the IPs."""
    if ip_address:
        process_ip(ip_address, output_file)
    elif input_file:
        process_ip_file(input_file, output_file)
    else:
        print("Please provide an IP address or input file to process.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Resolve DNS names for a list of IP addresses or a single IP address.")
    parser.add_argument('-a', '--address', help='Single IP address to resolve.')
    parser.add_argument('-i', '--input', help='Input file containing IP addresses.')
    parser.add_argument('-o', '--output', help='Output file to write the DNS results. If not specified, results are printed to the console.')

    args = parser.parse_args()
    main(args.address, args.input, args.output)