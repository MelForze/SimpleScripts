#!/usr/bin/env python3
import argparse
import base64
from Crypto.Cipher import AES

def decrypt(encrypted_data: str) -> str:
    """
    Decrypts an AES-256-CBC encrypted Base64 encoded string and returns the plaintext password.
    
    Args:
        encrypted_data (str): The Base64 encoded encrypted password.
    
    Returns:
        str: The decrypted password.
    """
    # Add missing padding if necessary for Base64 decoding
    missing_padding = (-len(encrypted_data)) % 4
    if missing_padding:
        encrypted_data += "=" * missing_padding

    # Decode the Base64 encoded encrypted data
    decoded = base64.b64decode(encrypted_data)

    # AES-256 key (32 bytes)
    key = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
    
    # Initialization vector (IV) for CBC mode; assuming IV of 16 zero bytes
    iv = b"\x00" * 16

    # Create a new AES cipher object in CBC mode with the given key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(decoded)

    # Remove PKCS#7 padding; the value of the last byte indicates the padding length
    padding_len = plaintext[-1]
    plaintext = plaintext[:-padding_len]

    # Convert from UTF-16LE encoded bytes to a string
    return plaintext.decode('utf-16le')

def main():
    """
    Parse command-line arguments and decrypt the provided encrypted password.
    """
    parser = argparse.ArgumentParser(description="Decrypt an AES-256-CBC encrypted password.")
    parser.add_argument('-p', '--password', required=True, help="Base64 encoded encrypted password.")
    args = parser.parse_args()

    try:
        decrypted = decrypt(args.password)
        print("Decrypted password:", decrypted)
    except Exception as e:
        print("An error occurred during decryption:", str(e))

if __name__ == "__main__":
    main()
