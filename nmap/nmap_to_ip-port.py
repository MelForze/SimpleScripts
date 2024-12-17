#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import argparse
import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def resolve_target(host):
    """Извлекает IP и домен из тега host, возвращая домен при его наличии, иначе IP."""
    ip = None
    domain = None

    # Извлечение IP адреса
    for address in host.findall('address'):
        addr = address.get('addr')
        if addr:
            ip = addr

    # Извлечение доменного имени
    for hostname in host.findall('./hostnames/hostname'):
        name = hostname.get('name')
        if name:
            domain = name

    return domain if domain else ip


def parse_nmap_xml(input_file, output_file):
    """Парсит XML-файл nmap и извлекает домен/IP и список открытых портов."""
    # Преобразование к абсолютным путям
    input_file = os.path.abspath(input_file)
    output_file = os.path.abspath(output_file)

    if not os.path.isfile(input_file):
        logging.error(f"Файл {input_file} не существует.")
        sys.exit(1)

    try:
        tree = ET.parse(input_file)
    except ET.ParseError as e:
        logging.error(f"Не удалось разобрать XML: {e}")
        sys.exit(1)

    root = tree.getroot()

    lines_to_write = []

    for host in root.findall('host'):
        target = resolve_target(host)
        if not target:
            logging.debug("Не удалось определить домен или IP для одного из хостов.")
            continue

        open_ports = []
        for port in host.findall('./ports/port'):
            state_element = port.find('state')
            if state_element is not None and state_element.get('state') == 'open':
                portid = port.get('portid')
                open_ports.append(portid)

        if open_ports:
            # Формируем строку вида: target [port1, port2, port3]
            ports_str = ', '.join(open_ports)
            line = f"{target} [{ports_str}]"
            lines_to_write.append(line)

    if not lines_to_write:
        logging.warning("Не найдено ни одного открытого порта или цели для вывода.")
    else:
        with open(output_file, 'w') as f:
            for line in lines_to_write:
                f.write(line + '\n')
        logging.info(f"Результат записан в {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Парсер nmap XML для извлечения домена/IP и открытых портов.')
    parser.add_argument('input_file', type=str, help='Входной XML файл')
    parser.add_argument('output_file', type=str, help='Выходной файл')

    args = parser.parse_args()
    parse_nmap_xml(args.input_file, args.output_file)


if __name__ == '__main__':
    main()
