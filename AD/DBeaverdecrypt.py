#!/usr/bin/env python3

import argparse
import json
import os
import sys


DEFAULT_PATHS = [
    "~/Library/DBeaverData/workspace6/General/.dbeaver/credentials-config.json",
    "~/.local/share/DBeaverData/workspace6/General/.dbeaver/credentials-config.json",
    "~/.local/share/.DBeaverData/workspace6/General/.dbeaver/credentials-config.json",
    "~/AppData/Roaming/DBeaverData/workspace6/General/.dbeaver/credentials-config.json",
]

PASSWORD_DECRYPTION_KEY = bytes(
    [186, 187, 74, 159, 119, 74, 184, 83, 201, 108, 45, 101, 61, 254, 84, 74]
)

RED = "\033[31m"
BLUE = "\033[34m"
RESET = "\033[0m"


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def print_banner():
    lines = [
        f"{RED} ____  ____                              ____                           _   {RESET}",
        f"{BLUE}|  _ \\| __ )  ___  __ ___   _____ _ __  |  _ \\  ___  ___ _ __ _   _ _ __| |_ {RESET}",
        f"{RED}| | | |  _ \\ / _ \\/ _` \\ \\ / / _ \\ '__| | | | |/ _ \\/ __| '__| | | | '_ \\ __|{RESET}",
        f"{BLUE}| |_| | |_) |  __/ (_| |\\ V /  __/ |    | |_| |  __/ (__| |  | |_| | |_) | |_ {RESET}",
        f"{RED}|____/|____/ \\___|\\__,_| \\_/ \\___|_|    |____/ \\___|\\___|_|   \\__, | .__/ \\__|{RESET}",
        f"{BLUE}                                                            |___/|_|          {RESET}",
    ]
    for line in lines:
        print(line)

    print(
        "\nDecrypt saved DBeaver credentials from credentials-config.json.\n"
    )


def parse_args(argv=None):
    parser = create_argument_parser(
        description="Decrypt DBeaver credentials-config.json."
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to credentials-config.json. If omitted, common default paths are checked.",
    )
    return parser.parse_args(argv)


def resolve_credentials_path(cli_path=None):
    if cli_path:
        return os.path.abspath(os.path.expanduser(cli_path))

    for path in DEFAULT_PATHS:
        candidate = os.path.expanduser(path)
        if os.path.isfile(candidate):
            return candidate

    return None


def load_aes():
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Missing dependency: install 'pycryptodome' to decrypt DBeaver credentials."
        ) from exc

    return AES


def remove_pkcs7_padding(data):
    if not data:
        raise ValueError("Encrypted payload is empty.")

    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid PKCS#7 padding length.")

    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid PKCS#7 padding bytes.")

    return data[:-padding_len]


def decrypt_bytes(data):
    if len(data) <= 16:
        raise ValueError("Encrypted file is too short to contain IV and ciphertext.")

    ciphertext = data[16:]
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of AES block size.")

    aes = load_aes()
    decryptor = aes.new(PASSWORD_DECRYPTION_KEY, aes.MODE_CBC, data[:16])
    padded_output = decryptor.decrypt(ciphertext)
    return remove_pkcs7_padding(padded_output)


def decrypt_file(filepath):
    with open(filepath, "rb") as handle:
        data = handle.read()
    return decrypt_bytes(data)


def format_output(plaintext):
    try:
        return json.dumps(json.loads(plaintext), indent=4, sort_keys=True)
    except (TypeError, ValueError, json.JSONDecodeError):
        return plaintext.decode("utf-8", errors="replace")


def main(argv=None):
    args = parse_args(argv)
    filepath = resolve_credentials_path(args.path)

    if not filepath:
        print(
            "Error: credentials-config.json not found. Provide a file path explicitly.",
            file=sys.stderr,
        )
        return 1

    if not os.path.isfile(filepath):
        print(f"Error: file not found: {filepath}", file=sys.stderr)
        return 1

    try:
        plaintext = decrypt_file(filepath)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_banner()
    print(format_output(plaintext))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
