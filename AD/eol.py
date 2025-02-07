#!/usr/bin/env python3

import json
import argparse
import os

def extract_unique_values(json_data, key):
    return set(entry[key] for entry in json_data)

def main(input_file):
    input_file_path = os.path.abspath(input_file)

    # Ensure the input file exists
    if not os.path.isfile(input_file_path):
        raise FileNotFoundError(f"File not found: {input_file_path}")

    # Чтение данных из файла с кодировкой utf-8-sig для обработки BOM
    with open(input_file_path, 'r', encoding='utf-8-sig') as file:
        data = json.load(file)

    # Извлечение уникальных операционных систем и имен хостов
    unique_operating_systems = extract_unique_values(data, "n.operatingsystem")
    unique_host_names = extract_unique_values(data, "n.name")

    # Получаем текущую рабочую директорию, откуда запускается скрипт
    current_working_dir = os.getcwd()

    # Определяем абсолютные пути для выходных файлов в текущей рабочей директории
    output_os_file = os.path.join(current_working_dir, 'unique_eol_systems.txt')
    output_name_file = os.path.join(current_working_dir, 'eol.txt')

    # Запись уникальных операционных систем в файл
    with open(output_os_file, 'w', encoding='utf-8') as file:
        for os_system in sorted(unique_operating_systems):
            file.write(f"{os_system}\n")

    # Запись уникальных имен хостов в файл
    with open(output_name_file, 'w', encoding='utf-8') as file:
        for name in sorted(unique_host_names):
            file.write(f"{name}\n")

    print(f"Unique operating systems written to: {output_os_file}")
    print(f"Unique host names written to: {output_name_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse JSON file and extract unique values.')
    parser.add_argument('input_file', type=str, help='Path to the input JSON file')

    args = parser.parse_args()
    main(args.input_file)