#!/usr/bin/env python3
import os
import sys
import argparse

def display_banner():
    print("""
██╗░░░░░███╗░░░███╗██╗░░██╗██╗░░░██╗███╗░░██╗████████╗███████╗██████╗░
██║░░░░░████╗░████║██║░░██║██║░░░██║████╗░██║╚══██╔══╝██╔════╝██╔══██╗
██║░░░░░██╔████╔██║███████║██║░░░██║██╔██╗██║░░░██║░░░█████╗░░██████╔╝
██║░░░░░██║╚██╔╝██║██╔══██║██║░░░██║██║╚████║░░░██║░░░██╔══╝░░██╔══██╗
███████╗██║░╚═╝░██║██║░░██║╚██████╔╝██║░╚███║░░░██║░░░███████╗██║░░██║
╚══════╝╚═╝░░░░░╚═╝╚═╝░░╚═╝░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝

Welcome to the LMHunteR Script!
""")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="This script reads an input file and creates two output files:\n"
                    "1. lm.txt - contains only the usernames.\n"
                    "2. lm_full.txt - contains full lines where the LM hash is not equal to 'aad3b435b51404eeaad3b435b51404ee'.",
        usage="./lm_hunter.py <file_path>"
    )
    parser.add_argument("file_path", type=str, help="Path to the input file")
    return parser.parse_args()

def filter_file(input_file):
    if not os.path.isfile(input_file):
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)
    line_count = 0
    try:
        with open(input_file, 'r') as in_file, open('lm.txt', 'w') as usernames_file, open('lm_full.txt', 'w') as full_file:
            for line in in_file:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(':')
                if len(parts) < 3:
                    continue
                username_domain = parts[0]
                lm_hash = parts[2].lower()
                if lm_hash != 'aad3b435b51404eeaad3b435b51404ee':
                    full_file.write(line + '\n')
                    username = username_domain.split('\\')[1] if '\\' in username_domain else username_domain
                    usernames_file.write(username + '\n')
                    line_count += 1
    except Exception as e:
        print(f"An error occurred while processing the files: {e}")
        sys.exit(1)
    print(f"\nNumber of detected lines: {line_count}")

def main():
    display_banner()
    args = parse_arguments()
    input_file = os.path.abspath(args.file_path)
    filter_file(input_file)

if __name__ == '__main__':
    main()
