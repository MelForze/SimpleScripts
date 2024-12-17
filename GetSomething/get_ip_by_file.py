#!/usr/bin/env python3

import re
import argparse
import os

def extract_ips(input_text):
    """Extract IPv4 addresses and subnets from the input text."""
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    subnet_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b'

    ips = re.findall(ipv4_pattern, input_text)
    subnets = re.findall(subnet_pattern, input_text)

    return ips + subnets

def unique_ips(input_ips):
    """Remove duplicates and sort the list of IPs and subnets."""
    return sorted(set(input_ips))

def save_to_file(output_file, data):
    """Write data to the specified output file."""
    output_file = os.path.abspath(output_file)
    try:
        with open(output_file, 'w') as file:
            for item in data:
                file.write("%s\n" % item)
        print(f"Unique IP addresses and subnets have been written to '{output_file}'")
    except IOError as e:
        print(f"Error writing to file '{output_file}': {e}")

def print_to_console(data):
    """Print data to the console."""
    print("Unique IP addresses and subnets:")
    for item in data:
        print(item)

def main(input_file, output_file=None):
    """Main function to process IPs from an input file and save or print them."""
    input_file = os.path.abspath(input_file)
    try:
        with open(input_file, 'r') as file:
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
    except IOError as e:
        print(f"Error reading file '{input_file}': {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract unique IPv4 addresses and subnets from a file.")
    parser.add_argument('-i', '--input', required=True, help='Input file path containing the data.')
    parser.add_argument('-o', '--output', help='(Optional) Output file path to save unique IP addresses and subnets. If not specified, results are printed to the console.')
    
    args = parser.parse_args()
    main(args.input, args.output)