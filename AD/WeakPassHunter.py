#!/usr/bin/env python3

import sys
import argparse
from collections import Counter
from rich.console import Console
from rich.table import Table

console = Console()

def print_banner() -> None:
    lines = [
        "[red] _       __           __   ____                  __  __            __           [/red]",
        "[blue]| |     / /__  ____ _/ /__/ __ \\____ ___________/ / / /_  ______  / /____  _____[/blue]",
        "[red]| | /| / / _ \\/ __ `/ //_/ /_/ / __ `/ ___/ ___/ /_/ / / / / __ \\/ __/ _ \\/ ___/[/red]",
        "[blue]| |/ |/ /  __/ /_/ / ,< / ____/ /_/ (__  |__  ) __  / /_/ / / / / /_/  __/ /    [/blue]",
        "[red]|__/|__/\\___/\\__,_/_/|_/_/    \\__,_/____/____/_/ /_/\\__,_/_/ /_/\\__/\\___/_/     [/red]",
        "[blue]                                                                                [/blue]"
    ]
    for line in lines:
        console.print(line, markup=True)
    
    description = (
        "This script outputs the number of cracked passwords and the top 5 most frequent passwords. "
        "It processes a file containing lines in the format: domain\\username:nthash:password or username:nthash:password."
    )
    console.print("\n" + description, style="bold white")

def process_input(lines):

    total_accounts = 0
    password_counter = Counter()
    compromised_entries = []
    
    for line in lines:
        line = line.rstrip("\n")
        if not line:
            continue
        
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        
        login = parts[0]
        if "\\" in login:
            username = login.split("\\")[-1]
        else:
            username = login
        
        password = parts[2]
        if password.strip() == "":
            password = ""
        
        total_accounts += 1
        password_counter[password] += 1
        compromised_entries.append((username, password))
    
    return total_accounts, password_counter, compromised_entries

def main():
    parser = argparse.ArgumentParser(
        usage="%(prog)s [options]",
        add_help=False,
        description="WeakpassHunter utility"
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        required=False,
        help="Path to the file with hashes. If omitted, reads from standard input."
    )
    parser.add_argument(
        "-t", "--top",
        type=int,
        default=5,
        help="Number of top frequent passwords to display (default: 5)"
    )
    parser.add_argument(
        "-s", "--save",
        action="store_true",
        help="Save compromised usernames to 'compromised.txt' and user:password pairs to 'user-pass.txt'"
    )
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    
    if len(sys.argv) == 1:
        print_banner()
        console.print("")
        parser.print_help()
        sys.exit(0)
    
    args = parser.parse_args()
    
    if args.help:
        print_banner()
        console.print("")
        parser.print_help()
        sys.exit(0)
    
    print_banner()
    console.print("")
    
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            console.print(f"Error opening file {args.file}: {e}", style="bold red")
            sys.exit(1)
    else:
        lines = sys.stdin.readlines()
    
    total_accounts, password_counter, compromised_entries = process_input(lines)
    
    effective_top = min(args.top, len(password_counter))
    
    console.print("\n" + "=" * 60 + "\n", style="bold white")
    console.print("Cracked passwords count: " + str(total_accounts), style="bold green")
    console.print("\nTop {} most frequent passwords:".format(effective_top), style="bold green")
    console.print("")
    
    table = Table(show_header=True, header_style="bold", show_edge=True)
    table.add_column("Password", no_wrap=True)
    table.add_column("Count", justify="right")
    
    for password, count in password_counter.most_common(effective_top):
        display_pass = password if password != "" else "<empty>"
        table.add_row(display_pass, str(count))
    
    console.print(table)
    console.print("")
    
    if args.save:
        try:
            with open("compromised.txt", "w", encoding="utf-8") as f:
                seen = set()
                for username, _ in compromised_entries:
                    if username not in seen:
                        f.write(username + "\n")
                        seen.add(username)
            
            with open("user-pass.txt", "w", encoding="utf-8") as f:
                for username, password in compromised_entries:
                    f.write(f"{username}:{password}\n")
            
            console.print("Saved compromised usernames to 'compromised.txt' and user:password pairs to 'user-pass.txt'.", style="bold yellow")
        except Exception as e:
            console.print(f"Error saving files: {e}", style="bold red")
            sys.exit(1)

if __name__ == "__main__":
    main()
