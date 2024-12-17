#!/usr/bin/env python3

import argparse
import socket
from ipwhois import IPWhois

def get_asn(domain):
    """Получает ASN для заданного домена."""
    try:
        ip_address = socket.gethostbyname(domain)
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        return result.get('asn')
    except Exception as e:
        print(f'Error fetching ASN for {domain}: {e}')
        return None

def process_domains(domains, output_file=None):
    """Обрабатывает список доменов и выводит результаты."""
    results = []
    for domain in domains:
        asn = get_asn(domain)
        if asn is not None:
            result = f'For domain {domain} ASN: {asn}'
            results.append(result)
            if output_file is None:
                print(result)
    
    if output_file is not None:
        with open(output_file, 'w') as f_out:
            for result in results:
                f_out.write(result + '\n')

def main(input_file=None, output_file=None, domain_list=None):
    """Основная функция обработки доменов."""
    if domain_list:
        domains = domain_list
    elif input_file:
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
    
    if domains:
        process_domains(domains, output_file)
    else:
        print("No domains to process.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Получение ASN для списка доменов.")
    parser.add_argument('-i', '--input', help='Файл с доменами.')
    parser.add_argument('-o', '--output', help='Файл для записи результатов. Если не указан, используется вывод в консоль.')
    parser.add_argument('-d', '--domains', nargs='+', help='Один или несколько доменов для обработки.')
    
    args = parser.parse_args()
    
    if not args.input and not args.domains:
        parser.print_help()
    else:
        main(args.input, args.output, args.domains)