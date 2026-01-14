#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/MelForze/SimpleScripts.git"
BRANCH="main"

DEST_DIR="${HOME}/scripts"

STATE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/simplescripts-installer"
CLONE_DIR="${STATE_DIR}/repo"
STAMP_FILE="${STATE_DIR}/deployed_commit"
MANIFEST_FILE="${STATE_DIR}/manifest.tsv"   # relpath<TAB>dest_filename

BEGIN_MARKER="# >>> simplescripts-installer >>>"
END_MARKER="# <<< simplescripts-installer <<<"

err() { printf 'ERROR: %s\n' "$*" >&2; }
info() { printf '%s\n' "$*"; }
blank() { printf '\n'; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Не найдено '$1'. Установи и повтори."; exit 1; }
}

ensure_dir() { mkdir -p "$1"; }

file_has_markers() {
  local f="$1"
  [ -f "$f" ] && grep -Fq "$BEGIN_MARKER" "$f"
}

append_path_block_if_missing() {
  local rcfile="$1"
  local block

  # Append to PATH (at the end) only if ~/scripts is not already in PATH
  block=$'if [ -d "$HOME/scripts" ]; then\n  case ":$PATH:" in\n    *":$HOME/scripts:"*) ;;\n    *) export PATH="$PATH:$HOME/scripts" ;;\n  esac\nfi'

  ensure_dir "$(dirname "$rcfile")"
  [ -f "$rcfile" ] || : > "$rcfile"

  if file_has_markers "$rcfile"; then
    return 0
  fi

  {
    blank
    info "$BEGIN_MARKER"
    printf '%s\n' "$block"
    info "$END_MARKER"
  } >> "$rcfile"
}

# --- manifest helpers (bash 3.2 compatible, no associative arrays) ---

manifest_get_dest() {
  # $1 = relpath
  [ -f "$MANIFEST_FILE" ] || return 0
  awk -F'\t' -v key="$1" '$1==key {print $2; exit}' "$MANIFEST_FILE" 2>/dev/null || true
}

manifest_dest_is_managed() {
  # $1 = dest_filename
  [ -f "$MANIFEST_FILE" ] || return 1
  awk -F'\t' -v d="$1" '$2==d {found=1; exit} END{exit(found?0:1)}' "$MANIFEST_FILE"
}

manifest_add_mapping() {
  # $1 = relpath, $2 = dest_filename
  ensure_dir "$(dirname "$MANIFEST_FILE")"
  printf "%s\t%s\n" "$1" "$2" >> "$MANIFEST_FILE"
}

sanitize_rel_to_name() {
  # Turn "Linux/foo bar.sh" -> "Linux__foo_bar.sh"
  local s="$1"
  s="${s//\//__}"
  s="${s// /_}"
  printf "%s" "$s"
}

pick_dest_name() {
  # $1 = relpath, $2 = base_filename
  local rel="$1"
  local base="$2"
  local dest="$base"

  # If we already mapped this file before, reuse the same destination name
  local mapped
  mapped="$(manifest_get_dest "$rel")"
  if [ -n "$mapped" ]; then
    printf "%s" "$mapped"
    return 0
  fi

  # If the destination name is free, use the base filename
  if [ ! -e "${DEST_DIR}/${dest}" ]; then
    printf "%s" "$dest"
    return 0
  fi

  # If the file exists but is managed by us, it's safe to overwrite it
  if manifest_dest_is_managed "$dest"; then
    printf "%s" "$dest"
    return 0
  fi

  # Otherwise it's likely the user's file — choose a safe name derived from the relative path
  dest="$(sanitize_rel_to_name "$rel")"

  # If even that name is taken by a non-managed file, add a numeric suffix
  if [ -e "${DEST_DIR}/${dest}" ] && ! manifest_dest_is_managed "$dest"; then
    local i=2
    local try
    while :; do
      try="${dest}__${i}"
      if [ ! -e "${DEST_DIR}/${try}" ] || manifest_dest_is_managed "$try"; then
        dest="$try"
        break
      fi
      i=$((i+1))
    done
  fi

  printf "%s" "$dest"
}

# --- repo sync/deploy ---

ensure_repo() {
  ensure_dir "$STATE_DIR"
  need_cmd git

  if [ -d "${CLONE_DIR}/.git" ]; then
    git -C "$CLONE_DIR" remote set-url origin "$REPO_URL" >/dev/null 2>&1 || true
    return 0
  fi

  # If the clone path exists but is not a git repo, back it up
  if [ -e "$CLONE_DIR" ] && [ ! -d "${CLONE_DIR}/.git" ]; then
    mv "$CLONE_DIR" "${CLONE_DIR}.backup.$(date +%Y%m%d%H%M%S)"
  fi

  info "Клонирую репозиторий (в служебную папку, не в ~/scripts)..."
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$CLONE_DIR" >/dev/null
}

repo_has_updates() {
  # returns 0 if updates exist, 1 if not
  git -C "$CLONE_DIR" fetch origin "$BRANCH" --quiet

  local local_sha remote_sha
  local_sha="$(git -C "$CLONE_DIR" rev-parse HEAD)"
  remote_sha="$(git -C "$CLONE_DIR" rev-parse "origin/${BRANCH}")"

  [ "$local_sha" != "$remote_sha" ]
}

repo_fast_forward() {
  # fast-forward only
  git -C "$CLONE_DIR" pull --ff-only origin "$BRANCH" >/dev/null
}

list_candidate_files() {
  # Treat everything except obvious docs/metadata as a "script-like" file
  find "$CLONE_DIR" -type f \
    -not -path "*/.git/*" \
    -not -path "*/.github/*" \
    -not -name ".gitignore" \
    -not -iname "readme*" \
    -not -iname "license*" \
    -not -iname "*.md" \
    -print
}

deploy_from_repo() {
  ensure_dir "$DEST_DIR"
  ensure_dir "$STATE_DIR"

  local commit
  commit="$(git -C "$CLONE_DIR" rev-parse HEAD)"

  # If we've already deployed this exact commit, do nothing
  if [ -f "$STAMP_FILE" ] && [ "$(cat "$STAMP_FILE")" = "$commit" ]; then
    info "Все обновлено."
    return 0
  fi

  info "Обновляю скрипты в ~/scripts (commit ${commit})..."

  # Copy files
  while IFS= read -r src; do
    local rel base dest_name dest_path
    rel="${src#"$CLONE_DIR"/}"
    base="$(basename "$rel")"
    dest_name="$(pick_dest_name "$rel" "$base")"
    dest_path="${DEST_DIR}/${dest_name}"

    cp -f "$src" "$dest_path"
    chmod +x "$dest_path"

    # Record mapping if it's new
    if [ -z "$(manifest_get_dest "$rel")" ]; then
      manifest_add_mapping "$rel" "$dest_name"
    fi
  done < <(list_candidate_files)

  printf "%s" "$commit" > "$STAMP_FILE"
  info "Готово."
}

usage() {
  cat <<'EOF'
Usage:
  install_simplescripts.sh [options]

Options:
  -h, --help   Show this help

What it does:
  - Creates ~/scripts
  - Appends ~/scripts to PATH (at the end) for bash (~/.bashrc) and zsh (~/.zshrc)
  - Clones SimpleScripts into a state directory (~/.local/share/simplescripts-installer/repo)
  - On updates, fast-forwards the git clone and deploys files "flattened" into ~/scripts
  - Makes deployed files executable (+x)
  - Does not overwrite your existing non-managed files; on name conflicts it uses names like Dir__file.sh

EOF
}

main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  ensure_dir "$DEST_DIR"

  # PATH (bash + zsh) — add only if our block is not present yet
  append_path_block_if_missing "${HOME}/.bashrc"
  append_path_block_if_missing "${HOME}/.zshrc"

  ensure_repo

  if repo_has_updates; then
    info "Найдены обновления — подтягиваю..."
    repo_fast_forward
    deploy_from_repo
  else
    # No repo updates; still do a first deploy if not deployed yet
    if [ -f "$STAMP_FILE" ]; then
      info "Все обновлено."
    else
      deploy_from_repo
    fi
  fi

  blank
  info "Чтобы PATH подхватился: открой новый терминал или выполни:"
  info "  source ~/.bashrc   # bash"
  info "  source ~/.zshrc    # zsh"
}

main "$@"