#!/usr/bin/env python3
import sys
import argparse
from passlib.hash import nthash

def banner():
    return (
        "\n"
        "███╗░░██╗████████╗░█████╗░██████╗░███████╗░█████╗░████████╗███████╗██████╗░\n"
        "████╗░██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗\n"
        "██╔██╗██║░░░██║░░░██║░░╚═╝██████╔╝█████╗░░███████║░░░██║░░░█████╗░░██████╔╝\n"
        "██║╚████║░░░██║░░░██║░░██╗██╔══██╗██╔══╝░░██╔══██║░░░██║░░░██╔══╝░░██╔══██╗\n"
        "██║░╚███║░░░██║░░░╚█████╔╝██║░░██║███████╗██║░░██║░░░██║░░░███████╗██║░░██║\n"
        "╚═╝░░╚══╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝\n"
    )

def compute_hash(password: str) -> str:
    return nthash.hash(password)

def parse_args():
    parser = argparse.ArgumentParser(description='Generate NTLM hash for a given password.')
    parser.add_argument('password', type=str, help='The password to generate the NTLM hash for')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0', help='Show program version')
    return parser.parse_args()

def main():
    print(banner())
    args = parse_args()
    try:
        print(f"NTLM Hash: {compute_hash(args.password)}")
    except Exception as error:
        print(f"Error computing NTLM hash: {error}")
        sys.exit(1)

if __name__ == "__main__":
    main()
