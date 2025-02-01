<div align="center">
<a href="https://ibb.co/mcnkMm2"><img src="https://i.ibb.co/2kzxfwC/2024-09-12-20-11-35.jpg" alt="2024-09-12-20-11-35" width="280" alt="BetterDisplay"></a>
<h2>Simple Scripts</h2>
</div>

import sys
import argparse
import itertools

def generate_variations(s):
    """
    Генерирует все вариации строки s, где для каждой буквы возможны варианты
    в нижнем и верхнем регистре. Не изменяет цифры и специальные символы.
    """
    # Для каждого символа: если это буква, варианты – нижний и верхний регистр,
    # иначе – сам символ.
    options = [(char.lower(), char.upper()) if char.isalpha() else (char,) for char in s]
    # itertools.product возвращает декартово произведение вариантов для каждого символа
    for variant in itertools.product(*options):
        yield ''.join(variant)

def main():
    parser = argparse.ArgumentParser(
        description="Генерация всех вариаций строки с изменением регистра букв."
    )
    parser.add_argument(
        '-i', '--input', type=str,
        help=("Входная строка или имя файла с входными строками. "
              "Если используется флаг --file, то значение воспринимается как имя файла.")
    )
    parser.add_argument(
        '-f', '--file', action='store_true',
        help="Указывает, что значение параметра --input является именем файла."
    )
    parser.add_argument(
        '-o', '--output', type=str,
        help="Имя файла для вывода результата. Если не указан, вывод производится в консоль."
    )
    args = parser.parse_args()

    # Определяем источник входных данных
    if args.input:
        if args.file:
            try:
                with open(args.input, 'r', encoding='utf-8') as f:
                    lines = [line.rstrip('\n') for line in f]
            except FileNotFoundError:
                print(f"Файл '{args.input}' не найден.", file=sys.stderr)
                sys.exit(1)
        else:
            # Если флаг --file не указан, рассматриваем значение как строку
            lines = [args.input]
    else:
        # Если входные данные не переданы, запрашиваем их у пользователя
        s = input("Введите строку: ")
        lines = [s]

    # Определяем способ вывода результата
    if args.output:
        try:
            output_target = open(args.output, 'w', encoding='utf-8')
        except IOError as e:
            print(f"Ошибка открытия файла для записи: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        output_target = sys.stdout

    # Обрабатываем каждую строку из входных данных
    for line in lines:
        output_target.write(f"Вариации для строки: {line}\n")
        for variation in generate_variations(line):
            output_target.write(variation + "\n")
        output_target.write('-' * 40 + "\n")

    if args.output:
        output_target.close()
        print(f"Результаты записаны в файл '{args.output}'.")

if __name__ == "__main__":
    main()