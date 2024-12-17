import re

def find_domains(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
        # Используем регулярное выражение для поиска доменных имен
        domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', content)
        # Убираем повторяющиеся доменные имена
        unique_domains = set(domains)
        return unique_domains

def write_to_file(domains, output_file):
    with open(output_file, 'w') as file:
        for domain in domains:
            file.write(domain + '\n')

if __name__ == "__main__":
    input_file_path = "all_domains.txt"
    output_file_path = "unique_domains.txt"

    unique_domains = find_domains(input_file_path)
    write_to_file(unique_domains, output_file_path)

    print(f"Уникальные доменные имена были записаны в {output_file_path}")
