#!/usr/bin/env python3

import argparse
import ipaddress
import os

def parse_ip_or_network(line: str):
    """
    Пытается интерпретировать строку как:
      1) IP-адрес (тогда добавляем /24)
      2) CIDR-сеть (строгая проверка отключена)
    Если обе проверки не прошли, возвращает None.
    """
    line = line.strip()
    if not line:
        return None
    
    # Сначала пробуем распарсить как одиночный IP-адрес
    try:
        ip = ipaddress.ip_address(line)
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        pass
    
    # Если это не IP, пробуем распарсить как сеть (CIDR)
    try:
        network = ipaddress.ip_network(line, strict=False)
        return network
    except ValueError:
        print(f"Invalid IP address or network: {line}")
        return None

def get_unique_subnets(input_file: str):
    """Возвращает отсортированный список уникальных сетей из входного файла."""
    subnets = set()
    try:
        with open(input_file, 'r') as f:
            for line in f:
                network = parse_ip_or_network(line)
                if network:
                    subnets.add(network)
    except OSError as e:
        print(f"Error reading file '{input_file}': {e}")
        return []
    
    return sorted(subnets, key=lambda x: (x.network_address, x.prefixlen))

def save_to_file(output_file: str, subnets):
    """Сохраняет список сетей в файл."""
    try:
        with open(output_file, 'w') as file:
            for subnet in subnets:
                file.write(f"{subnet}\n")
        print(f"Unique subnets have been written to '{output_file}'")
    except OSError as e:
        print(f"Error writing to file '{output_file}': {e}")

def print_to_console(subnets):
    """Печатает список сетей в консоль."""
    print("Unique subnets:")
    for subnet in subnets:
        print(subnet)

def main(input_file: str, output_file: str = None):
    """Основная функция."""
    # Превращаем путь в абсолютный для надёжности
    input_file = os.path.abspath(input_file)
    
    unique_subnets = get_unique_subnets(input_file)
    if not unique_subnets:
        print("No valid subnets were found.")
        return

    if output_file:
        save_to_file(output_file, unique_subnets)
    else:
        print_to_console(unique_subnets)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Get unique subnets from a list of IP addresses.'
    )
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Input file with list of IP addresses'
    )
    parser.add_argument(
        '-o', '--output',
        help='(Optional) Output file to save unique subnets. '
             'If not specified, results are printed to the console.'
    )

    args = parser.parse_args()
    # Вызов main с учетом правильного названия аргумента
    main(args.input, args.output)
