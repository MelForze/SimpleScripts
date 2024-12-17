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


def build_url(target, port_element):
    """Формирует URL исходя из информации о порте и сервисе."""
    portid = port_element.get('portid')
    state_element = port_element.find('state')
    service_element = port_element.find('service')

    if state_element is None or service_element is None:
        return None

    state = state_element.get('state')
    if state != 'open':
        return None

    service = service_element.get('name')
    tunnel = service_element.get('tunnel')

    # Логика определения URL
    # Предполагается, что при http(s) портах будет понятен протокол.
    # Если tunnel = 'ssl', предполагается https, иначе http.
    protocol = None
    if service in ('http', 'https'):
        if service == 'https' or tunnel == 'ssl':
            protocol = 'https'
        else:
            protocol = 'http'
    elif service == 'unknown' and tunnel == 'ssl':
        # Случай, когда сервис неизвестен, но tunnel = 'ssl' подразумевает https
        protocol = 'https'

    if protocol is None:
        # Сервис не относится к http/https
        return None

    # Установка URL с учетом порта
    default_port = '443' if protocol == 'https' else '80'
    if portid == default_port:
        url = f"{protocol}://{target}"
    else:
        url = f"{protocol}://{target}:{portid}"

    return url


def parse_nmap_xml(input_file, output_file):
    """Парсит XML-файл nmap и извлекает URL для http/https сервисов."""
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

    extracted_urls = []

    for host in root.findall('host'):
        target = resolve_target(host)
        if not target:
            logging.debug("Не удалось определить цель (IP или домен) для одного из хостов.")
            continue

        for port in host.findall('./ports/port'):
            url = build_url(target, port)
            if url:
                extracted_urls.append(url)

    if not extracted_urls:
        logging.warning("Не найдено ни одного подходящего URL.")
    else:
        # Запись результатов в файл
        with open(output_file, 'w') as f:
            for url in extracted_urls:
                f.write(url + '\n')
        logging.info(f"URLs были записаны в {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Парсер nmap XML для извлечения URLs.')
    parser.add_argument('input_file', type=str, help='Входной XML файл')
    parser.add_argument('output_file', type=str, help='Выходной файл для записи URL')

    args = parser.parse_args()

    parse_nmap_xml(args.input_file, args.output_file)


if __name__ == '__main__':
    main()
