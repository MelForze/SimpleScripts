import sys

def convert_mixed_file_to_hashes(input_file, output_file):
    """
    Read a file that may contain lines from either opasswd or shadow,
    extract hashes, and save them in a Hashcat-friendly format.
    """
    try:
        with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
            for line in f_in:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Split the line by colons.
                parts = line.split(':')
                
                # Detect the record format:
                # - 'shadow' usually has more than 8 fields and the hash is in field 2.
                # - 'opasswd' usually has fewer fields and the hashes are in the last field.
                if len(parts) > 2 and parts[1].startswith('$'):
                    # Shadow line.
                    hash_field = parts[1]
                elif len(parts) >= 2:
                    # opasswd line.
                    hash_field = parts[-1]
                else:
                    # Unknown line format; skip it.
                    continue 

                # Split the extracted hash field into individual hashes.
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
