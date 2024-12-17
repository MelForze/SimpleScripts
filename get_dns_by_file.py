#!/usr/bin/env python3

import re
import argparse
import os

def find_domains(file_path):
    """Find and return a set of unique domain names from a file."""
    unique_domains = set()
    try:
        file_path = os.path.abspath(file_path)
        with open(file_path, 'r') as file:
            content = file.read()
            if not content.strip():
                print(f"Warning: Input file '{file_path}' is empty.")
                return unique_domains
            # Use a regex to find domain names
            domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', content)
            if not domains:
                print(f"No domain names found in the input file '{file_path}'.")
            # Remove duplicate domain names, case-insensitively
            unique_domains = set(domain.lower() for domain in domains)
    except FileNotFoundError:
        print(f"Error: Input file '{file_path}' not found.")
    except IOError as e:
        print(f"Error reading file '{file_path}': {e}")
    return unique_domains

def write_to_file(domains, output_file):
    """Write unique domain names to a specified output file."""
    output_file = os.path.abspath(output_file)
    try:
        with open(output_file, 'w') as file:
            for domain in sorted(domains):
                file.write(domain + '\n')
        print(f"Unique domain names have been written to {output_file}")
    except IOError as e:
        print(f"Error writing to file '{output_file}': {e}")

def output_to_console(domains):
    """Print unique domain names to the console."""
    if domains:
        print("Unique domain names:")
        for domain in sorted(domains):
            print(domain)

def main(input_file=None, output_file=None):
    """Main function to find and save unique domain names."""
    if not input_file:
        print("Input file must be specified.")
        return

    unique_domains = find_domains(input_file)
    
    if unique_domains:
        if output_file:
            write_to_file(unique_domains, output_file)
        else:
            output_to_console(unique_domains)
    else:
        print("No unique domains found to output.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract unique domain names from a file and optionally write them to an output file.")
    parser.add_argument('-i', '--input', required=True, help='Input file path containing domain data.')
    parser.add_argument('-o', '--output', help='Output file path to save unique domain names. If not specified, results are printed to the console.')
    
    args = parser.parse_args()
    main(args.input, args.output)