#!/usr/bin/env python3

import os
import argparse

def extract_ports(file_path):
    open_ports = []
    
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("open tcp"):
                parts = line.split()
                if len(parts) > 2:
                    port = parts[2]
                    open_ports.append(int(port))  # Преобразуем строковый номер порта в целое число
    
    return open_ports

def generate_command(open_ports):
    open_ports = sorted(open_ports)  # Сортируем порты по возрастанию
    base_command = "sudo nmap -Pn -sS -sV -sC --version-all -p {ports} --min-rate 1000 --max-retries 1 -v -oA nmap/scopea_domains -iL domains.txt"
    ports_string = ','.join(map(str, open_ports))  # Преобразуем каждый порт обратно в строку для команды
    return base_command.format(ports=ports_string)

def main():
    parser = argparse.ArgumentParser(description="Extract open ports from a file and generate an nmap command.")
    parser.add_argument('file', type=str, help="Path to the input file")
    args = parser.parse_args()

    file_path = os.path.abspath(args.file)

    if not os.path.isfile(file_path):
        print(f"Error: The file {file_path} does not exist.")
        return
    
    open_ports = extract_ports(file_path)
    
    if open_ports:
        command = generate_command(open_ports)
        print("Generated command:")
        print(command)
    else:
        print("No open ports found in the file.")

if __name__ == "__main__":
    main()