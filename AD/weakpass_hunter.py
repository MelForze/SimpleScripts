#!/usr/bin/env python3

import re
import sys
from collections import Counter

BANNER = """
***********************************************
*      Password Extraction and Analysis       *
*                Version 1.0                  *
***********************************************
"""

HELP_MESSAGE = """
Usage:  ./weakpass_hunter.py [options] <filename>

Options:
  -h, --help    Show this help message and exit
  <filename>    Path to the file for processing
"""

def extract_passwords(file_path):
    """
    Extracts passwords from a given file, handling lines with or without a domain.

    Parameters:
    - file_path: Path to the input file containing the data.

    Returns:
    - A list of extracted passwords.
    """
    # Modified pattern to match lines with or without a domain
    password_pattern = re.compile(r'^(?:[^\\]+\\)?[^:]+:[^:]*:(.+)$')
    passwords = []

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                match = password_pattern.match(line)
                if match:
                    password = match.group(1)
                    passwords.append(password)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading the file '{file_path}': {e}")
        sys.exit(1)
    
    return passwords

def top_five_passwords(passwords):
    """
    Finds the top five most common passwords.

    Parameters:
    - passwords: A list of passwords.

    Returns:
    - A list of tuples containing the five most common passwords and their counts.
    """
    counter = Counter(passwords)
    return counter.most_common(5)

def main():
    """Main function executing the script's logic."""
    print(BANNER)

    if len(sys.argv) < 2:
        print(HELP_MESSAGE)
        sys.exit(1)

    if sys.argv[1] in ('-h', '--help'):
        print(HELP_MESSAGE)
        sys.exit(0)

    file_path = sys.argv[1]
    passwords = extract_passwords(file_path)
    most_common_passwords = top_five_passwords(passwords)

    if most_common_passwords:
        print("\nTop 5 most common passwords:")
        for password, count in most_common_passwords:
            print(f"Password: {password}, Occurrences: {count}")
    else:
        print("No passwords were found in the specified file.")

if __name__ == "__main__":
    main()