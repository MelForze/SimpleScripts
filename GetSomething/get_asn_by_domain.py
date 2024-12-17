#!/usr/bin/env python3

import argparse
import socket
from ipwhois import IPWhois

def get_asn(domain):
    """Retrieves the ASN for a given domain."""
    try:
        ip_address = socket.gethostbyname(domain)
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        return result.get('asn')
    except Exception as e:
        print(f'Error fetching ASN for {domain}: {e}')
        return None

def process_domains(domains, output_file=None):
    """Processes a list of domains and outputs the results."""
    results = []
    for domain in domains:
        asn = get_asn(domain)
        if asn is not None:
            result = f'For domain {domain} ASN: {asn}'
            results.append(result)
            if output_file is None:
                print(result)
    
    if output_file is not None:
        with open(output_file, 'w') as f_out:
            for result in results:
                f_out.write(result + '\n')

def main(input_file=None, output_file=None, domain_list=None):
    """Main function for domain processing."""
    if domain_list:
        domains = domain_list
    elif input_file:
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
    
    if domains:
        process_domains(domains, output_file)
    else:
        print("No domains to process.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrieves ASN for a list of domains.")
    parser.add_argument('-i', '--input', help='File with domains.')
    parser.add_argument('-o', '--output', help='File to write results. If not specified, the console is used.')
    parser.add_argument('-d', '--domains', nargs='+', help='One or more domains to process.')
    
    args = parser.parse_args()
    
    if not args.input and not args.domains:
        parser.print_help()
    else:
        main(args.input, args.output, args.domains)