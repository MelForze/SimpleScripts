#!/usr/bin/env python3

import argparse
import os
import sys

def display_banner():
    """Displays the introductory banner for the script."""
    banner = """
    *********************************************
    *       Compromised Usernames Scanner       *
    *********************************************
    Usage: ./crackNT_to_usernames.py <input_file>
    """
    print(banner)

def load_usernames(filename):
    """
    Loads a list of usernames from a specified file.
    
    Parameters:
    - filename: The path to the file containing usernames.
    
    Returns:
    - A set containing all usernames in lowercase.
    """
    try:
        with open(filename, 'r') as file:
            return {line.strip().lower() for line in file}
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: An error occurred while reading '{filename}': {e}")
        sys.exit(1)

def find_compromised_usernames_and_passwords(filename):
    """
    Identifies compromised usernames and passwords from a given file.
    
    Parameters:
    - filename: The path to the input file.
    
    Returns:
    - A tuple containing a set of compromised usernames and a list of username-password pairs.
    """
    compromised_usernames = set()
    username_password_pairs = []

    try:
        with open(filename, 'r') as file:
            for line in file:
                parts = line.strip().split(':')
                if len(parts) == 3:
                    domain_username, _, password = parts
                    username = domain_username.split('\\')[-1].lower()
                    compromised_usernames.add(username)
                    username_password_pairs.append(f"{username}:{password}")
    except Exception as e:
        print(f"Error: An error occurred while reading '{filename}': {e}")
        sys.exit(1)

    return compromised_usernames, username_password_pairs

def save_results(compromised_usernames, username_password_pairs):
    """
    Saves the results to output files.
    
    Parameters:
    - compromised_usernames: A set of compromised usernames.
    - username_password_pairs: A list of username-password combinations.
    """
    try:
        with open('compromised.txt', 'w') as usr_file:
            usr_file.write('\n'.join(compromised_usernames) + '\n')

        with open('username-password.txt', 'w') as pair_file:
            pair_file.write('\n'.join(username_password_pairs) + '\n')

        print("Results saved to compromised.txt and username-password.txt")
    except Exception as e:
        print(f"Error: An error occurred while writing results: {e}")
        sys.exit(1)

def main(input_file):
    """Main program logic."""
    compromised_usernames, username_password_pairs = find_compromised_usernames_and_passwords(input_file)
    save_results(compromised_usernames, username_password_pairs)

if __name__ == '__main__':
    display_banner()
    
    parser = argparse.ArgumentParser(description='Scan for compromised usernames and passwords in a file and store results in compromised.txt and username-password.txt')
    parser.add_argument('input', type=str, help='Path to the input file')

    if len(sys.argv) <= 1:
        print("Error: No input file provided.\n")
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    input_file = os.path.abspath(args.input)
    
    main(input_file)