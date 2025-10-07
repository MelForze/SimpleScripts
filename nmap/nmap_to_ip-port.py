#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import argparse
import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def resolve_target(host):
    """
    Return the hostname if present; otherwise return an IP address.
    When selecting an IP, prefer addrtype in this order: ipv4, then ipv6.
    If neither ipv4 nor ipv6 is found, return any available addr.
    """
    ipv4_addrs = []
    ipv6_addrs = []
    other_addrs = []
    domain = None

    # Collect addresses by type
    for address in host.findall('address'):
        addr = address.get('addr')
        atype = (address.get('addrtype') or '').lower()
        if not addr:
            continue
        if atype == 'ipv4':
            ipv4_addrs.append(addr)
        elif atype == 'ipv6':
            ipv6_addrs.append(addr)
        else:
            other_addrs.append(addr)

    # Use hostname if available
    for hostname in host.findall('./hostnames/hostname'):
        name = hostname.get('name')
        if name:
            domain = name
            break

    if domain:
        return domain

    # Preference order: ipv4 -> ipv6 -> any other addr
    if ipv4_addrs:
        return ipv4_addrs[0]
    if ipv6_addrs:
        return ipv6_addrs[0]
    if other_addrs:
        return other_addrs[0]

    return None

def parse_nmap_xml(input_file, output_file, https_filter):
    input_file = os.path.abspath(input_file)
    output_file = os.path.abspath(output_file)
    if not os.path.isfile(input_file):
        logging.error(f"File {input_file} does not exist.")
        sys.exit(1)
    try:
        tree = ET.parse(input_file)
    except ET.ParseError as e:
        logging.error(f"Failed to parse XML: {e}")
        sys.exit(1)
    root = tree.getroot()
    lines_to_write = []
    for host in root.findall('host'):
        target = resolve_target(host)
        if not target:
            logging.debug("Failed to determine domain or IP for a host.")
            continue
        open_ports = []
        for port in host.findall('./ports/port'):
            state_element = port.find('state')
            if state_element is not None and state_element.get('state') == 'open':
                if https_filter:
                    service = port.find('service')
                    if service is None or service.get('name', '').lower() != 'https':
                        continue
                portid = port.get('portid')
                open_ports.append(portid)
        if open_ports:
            ports_str = ', '.join(open_ports)
            line = f"{target} [{ports_str}]"
            lines_to_write.append(line)
    if not lines_to_write:
        logging.warning("No open ports or targets found for output.")
    else:
        try:
            with open(output_file, 'w') as f:
                for line in lines_to_write:
                    f.write(line + '\n')
            logging.info(f"Output written to {output_file}")
        except IOError as e:
            logging.error(f"Error writing to file {output_file}: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Nmap XML parser to extract domain/IP and open ports.')
    parser.add_argument('-i', '--input', required=True, type=str, help='Input XML file')
    parser.add_argument('-o', '--output', required=True, type=str, help='Output file')
    parser.add_argument('--https', action='store_true', help='Output only ports with https service')
    args = parser.parse_args()
    parse_nmap_xml(args.input, args.output, args.https)

if __name__ == '__main__':
    main()