#!/usr/bin/env python3

import os
import sys

def display_banner():
    banner = """

██╗░░░░░███╗░░░███╗██╗░░██╗██╗░░░██╗███╗░░██╗████████╗███████╗██████╗░
██║░░░░░████╗░████║██║░░██║██║░░░██║████╗░██║╚══██╔══╝██╔════╝██╔══██╗
██║░░░░░██╔████╔██║███████║██║░░░██║██╔██╗██║░░░██║░░░█████╗░░██████╔╝
██║░░░░░██║╚██╔╝██║██╔══██║██║░░░██║██║╚████║░░░██║░░░██╔══╝░░██╔══██╗
███████╗██║░╚═╝░██║██║░░██║╚██████╔╝██║░╚███║░░░██║░░░███████╗██║░░██║
╚══════╝╚═╝░░░░░╚═╝╚═╝░░╚═╝░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝

Welcome to the LMHunteR Script!
"""
    print(banner)

def show_help():
    help_text = """
Usage: ./lm_hunter.py <file_path>

Options:
  -h                        Show this help message.

Description:
  This script reads an input file and creates two output files:
  1. lm.txt       - contains only the usernames.
  2. lm_full.txt  - contains full lines where the LM hash is not equal to 'aad3b435b51404eeaad3b435b51404ee'.
"""
    print(help_text)

def filter_file(input_file):
    if not os.path.isfile(input_file):
        print(f"Error: File '{input_file}' not found.")
        return

    line_count = 0

    try:
        with open(input_file, 'r') as in_file, \
             open('lm.txt', 'w') as usernames_file, \
             open('lm_full.txt', 'w') as full_file:
            
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
    else:
        print(f"\nNumber of detected lines: {line_count}")

def main():
    display_banner()

    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] == '-h'):
        show_help()
        sys.exit(0)

    if len(sys.argv) != 2:
        print("Error: Incorrect number of arguments.\n")
        show_help()
        sys.exit(1)

    input_file = os.path.abspath(sys.argv[1])
    filter_file(input_file)

if __name__ == '__main__':
    main()