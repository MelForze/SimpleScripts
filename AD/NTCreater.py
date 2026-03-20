#!/usr/bin/env python3
import argparse
import hashlib
import shutil
import subprocess
import sys


AES128_KEY_SIZE = 16
AES256_KEY_SIZE = 32
KERBEROS_PBKDF2_ITERATIONS = 4096
# RFC 3961: 128-fold("kerberos")
KERBEROS_DK_CONSTANT = bytes.fromhex("6b65726265726f737b9b5b2b93132b93")


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def banner():
    return (
        "\n"
        "███╗░░██╗████████╗░█████╗░██████╗░███████╗░█████╗░████████╗███████╗██████╗░\n"
        "████╗░██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗\n"
        "██╔██╗██║░░░██║░░░██║░░╚═╝██████╔╝█████╗░░███████║░░░██║░░░█████╗░░██████╔╝\n"
        "██║╚████║░░░██║░░░██║░░██╗██╔══██╗██╔══╝░░██╔══██║░░░██║░░░██╔══╝░░██╔══██╗\n"
        "██║░╚███║░░░██║░░░╚█████╔╝██║░░██║███████╗██║░░██║░░░██║░░░███████╗██║░░██║\n"
        "╚═╝░░╚══╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝\n"
    )


def load_nthash():
    try:
        from passlib.hash import nthash
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Missing dependency: install 'passlib' to use NTCreater."
        ) from exc
    return nthash


def compute_hash(password: str) -> str:
    return load_nthash().hash(password)


def build_kerberos_salt(domain: str, user: str) -> str:
    return domain.upper() + user

def try_load_aes():
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError:
        return None
    return AES


def openssl_encrypt_block(key: bytes, block: bytes) -> bytes:
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        raise RuntimeError(
            "Missing AES backend: install 'pycryptodome' or ensure 'openssl' is available."
        )

    if len(block) != 16:
        raise ValueError("AES block encryption requires a 16-byte block.")

    if len(key) == AES128_KEY_SIZE:
        cipher_name = "-aes-128-ecb"
    elif len(key) == AES256_KEY_SIZE:
        cipher_name = "-aes-256-ecb"
    else:
        raise ValueError("Unsupported AES key length.")

    completed = subprocess.run(
        [openssl_path, "enc", cipher_name, "-nopad", "-nosalt", "-K", key.hex()],
        input=block,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        error_message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"OpenSSL AES backend failed: {error_message or 'unknown error'}")
    return completed.stdout


def encrypt_aes_block(key: bytes, block: bytes) -> bytes:
    aes = try_load_aes()
    if aes is not None:
        return aes.new(key, aes.MODE_ECB).encrypt(block)
    return openssl_encrypt_block(key, block)


def derive_kerberos_aes_key(
    password: str,
    salt: str,
    key_size: int,
    iterations: int = KERBEROS_PBKDF2_ITERATIONS,
) -> str:
    if key_size not in {AES128_KEY_SIZE, AES256_KEY_SIZE}:
        raise ValueError("AES key size must be 16 or 32 bytes.")
    if iterations < 1:
        raise ValueError("PBKDF2 iterations must be at least 1.")

    base_key = hashlib.pbkdf2_hmac(
        "sha1",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=key_size,
    )

    derived = bytearray()
    block = KERBEROS_DK_CONSTANT
    while len(derived) < key_size:
        block = encrypt_aes_block(base_key, block)
        derived.extend(block)

    return bytes(derived[:key_size]).hex()


def compute_ad_keys(password: str, domain: str, user: str):
    salt = build_kerberos_salt(domain, user)
    return {
        "salt": salt,
        "aes128": derive_kerberos_aes_key(password, salt, AES128_KEY_SIZE),
        "aes256": derive_kerberos_aes_key(password, salt, AES256_KEY_SIZE),
    }


def parse_args(argv=None):
    parser = create_argument_parser(
        description="Generate NTLM hash and optional Kerberos AES keys for a given password."
    )
    parser.add_argument(
        "password_value",
        nargs="?",
        metavar="password",
        help="The password to generate the NTLM hash for.",
    )
    parser.add_argument(
        "-p",
        "--password",
        dest="password_flag",
        metavar="password",
        help="The password to generate the NTLM hash for.",
    )
    parser.add_argument(
        "-d",
        "--domain",
        help="AD domain / Kerberos realm used to derive AES keys.",
    )
    parser.add_argument(
        "-u",
        "--username",
        help="Username used to derive Kerberos AES keys.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show additional debug output such as the Kerberos salt.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s 1.0",
        help="Show program version",
    )

    args = parser.parse_args(argv)
    if args.password_value and args.password_flag is not None:
        parser.error("Use either positional password or -p/--password, not both.")
    if args.password_flag is not None:
        args.password = args.password_flag
    elif args.password_value is not None:
        args.password = args.password_value
    else:
        parser.error("A password is required. Use positional input or -p/--password.")

    args.user = args.username
    if bool(args.domain) != bool(args.username):
        parser.error("Use both -d/--domain and -u/--username to calculate AES keys.")

    return args


def main(argv=None):
    print(banner())
    args = parse_args(argv)
    try:
        print(f"NTLM Hash: {compute_hash(args.password)}")
        if args.username:
            ad_keys = compute_ad_keys(args.password, args.domain, args.user)
            if args.debug:
                print(f"Kerberos Salt: {ad_keys['salt']}")
            print(f"AES128 Key: {ad_keys['aes128']}")
            print(f"AES256 Key: {ad_keys['aes256']}")
    except Exception as error:
        print(f"Error generating credentials: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
