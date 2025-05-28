import sys

def convert_mixed_file_to_hashes(input_file, output_file):
    """
    Читает файл, который может содержать строки как из opasswd, так и из shadow, 
    извлекает хэши и сохраняет их для использования с Hashcat.
    """
    try:
        with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
            for line in f_in:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Разделяем строку по двоеточиям
                parts = line.split(':')
                
                # Определяем формат:
                # - В 'shadow' обычно больше 8 полей и хэш находится во втором поле.
                # - В 'opasswd' обычно меньше полей, и хэши в последнем.
                if len(parts) > 2 and parts[1].startswith('$'):
                    # Строка из shadow
                    hash_field = parts[1]
                elif len(parts) >= 2:
                    # Строка из opasswd
                    hash_field = parts[-1]
                else:
                    # Неизвестная строка, можем её игнорировать
                    continue 

                # Разбор хэшей
                hashes = [h.strip() for h in hash_field.split(',') if h.strip()]

                for h in hashes:
                    f_out.write(h + '\n')

        print(f"[+] Успешно сохранено в {output_file}")
    except Exception as e:
        print(f"[-] Ошибка: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python3 script.py <input_file> <output_hashes>")
        sys.exit(1)
    
    convert_mixed_file_to_hashes(sys.argv[1], sys.argv[2])