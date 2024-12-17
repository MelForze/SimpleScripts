#!/usr/bin/env python3

import sys
import argparse
from passlib.hash import nthash

def print_banner():
    """Prints the program banner."""
    banner = """

███╗░░██╗████████╗░█████╗░██████╗░███████╗░█████╗░████████╗███████╗██████╗░
████╗░██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗
██╔██╗██║░░░██║░░░██║░░╚═╝██████╔╝█████╗░░███████║░░░██║░░░█████╗░░██████╔╝
██║╚████║░░░██║░░░██║░░██╗██╔══██╗██╔══╝░░██╔══██║░░░██║░░░██╔══╝░░██╔══██╗
██║░╚███║░░░██║░░░╚█████╔╝██║░░██║███████╗██║░░██║░░░██║░░░███████╗██║░░██║
╚═╝░░╚══╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝
    """
    print(banner)

def compute_ntlm_hash(password: str) -> str:
    """Computes the NTLM hash for the given password."""
    return nthash.hash(password)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Generate NTLM hash for a given password.')
    parser.add_argument('password', type=str, help='The password to generate the NTLM hash for')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0', help='Show program version')

    args = parser.parse_args()

    try:
        ntlm_hash = compute_ntlm_hash(args.password)
        print(f"NTLM Hash: {ntlm_hash}")
    except Exception as e:
        print(f"Error computing NTLM hash: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()