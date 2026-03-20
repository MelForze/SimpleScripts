#!/usr/bin/env python3

import argparse
import base64
import binascii
import sys


PASSWORD_DECRYPTION_KEY = (
    b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"
    b"\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
)
IV = b"\x00" * 16


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def load_aes():
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Missing dependency: install 'pycryptodome' to decrypt GPP passwords."
        ) from exc

    return AES


def decode_ciphertext(encrypted_data: str) -> bytes:
    normalized = encrypted_data.strip()
    missing_padding = (-len(normalized)) % 4
    if missing_padding:
        normalized += "=" * missing_padding

    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64-encoded password.") from exc

    if not decoded:
        raise ValueError("Encrypted payload is empty.")
    if len(decoded) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of AES block size.")

    return decoded


def remove_pkcs7_padding(data: bytes) -> bytes:
    if not data:
        raise ValueError("Decrypted payload is empty.")

    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid PKCS#7 padding length.")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid PKCS#7 padding bytes.")

    return data[:-padding_len]


def decrypt(encrypted_data: str) -> str:
    decoded = decode_ciphertext(encrypted_data)
    aes = load_aes()
    cipher = aes.new(PASSWORD_DECRYPTION_KEY, aes.MODE_CBC, IV)
    plaintext = cipher.decrypt(decoded)
    unpadded = remove_pkcs7_padding(plaintext)

    try:
        return unpadded.decode("utf-16le")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted payload is not valid UTF-16LE text.") from exc


def parse_args(argv=None) -> argparse.Namespace:
    parser = create_argument_parser(
        description="Decrypt an AES-256-CBC encrypted password."
    )
    parser.add_argument(
        "-p",
        "--password",
        required=True,
        help="Base64 encoded encrypted password.",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    try:
        decrypted = decrypt(args.password)
    except (RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Decrypted password: {decrypted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
