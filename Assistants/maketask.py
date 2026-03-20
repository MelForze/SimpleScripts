#!/usr/bin/env python3

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


INVALID_PROJECT_CHARS = set('<>:"/\\|?*')
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}
EXTERNAL_DIRS = [
    "bbot_active",
    "bbot_passive",
    "ffuf",
    "httpx",
    "katana",
    "masscan",
    "nessus",
    "nmap",
    "nuclei",
    "subdomains",
]

INTERNAL_DIRS = [
    "ffuf",
    "httpx",
    "katana",
    "masscan",
    "nessus",
    "nmap",
    "nuclei",
]

AD_DIRS = [
    "ad_office",
    "ad_pci",
]

MOBILE_DIRS = [
    "Android",
    "iOS",
]


class ProjectCreationError(Exception):
    pass


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def usage_text(script_name: str) -> str:
    return (
        f"Usage:\n"
        f"  {script_name} <project-name>\n\n"
        f"Description:\n"
        f"  Interactive script for creating a pentest project directory structure.\n\n"
        f"Options:\n"
        f"  -h, --help      Show this help message and exit\n\n"
        f"Example:\n"
        f"  {script_name} ACME-Pentest-2025\n"
    )


def ask_yn(prompt: str) -> bool:
    while True:
        try:
            answer = input(f"{prompt} (Y/N): ").strip().lower()
        except EOFError as exc:
            raise ProjectCreationError(
                "Input stream ended unexpectedly while waiting for an answer."
            ) from exc

        if answer == "y":
            return True
        if answer == "n":
            return False
        print("Please enter Y or N.")


def validate_project_name(project_name: str) -> None:
    if not project_name:
        raise ProjectCreationError("Project name is required.")
    if project_name in {".", "..", "/", "\\"}:
        raise ProjectCreationError(
            f"Invalid project name: '{project_name}' "
            "(must be a simple folder name)"
        )
    if project_name != project_name.strip() or project_name.endswith("."):
        raise ProjectCreationError(
            f"Invalid project name: '{project_name}' "
            "(must not start/end with spaces or end with a dot)"
        )
    if any(char in INVALID_PROJECT_CHARS for char in project_name):
        raise ProjectCreationError(
            f"Invalid project name: '{project_name}' "
            "(contains characters that are unsafe on common filesystems)"
        )
    if any(ord(char) < 32 for char in project_name):
        raise ProjectCreationError(
            f"Invalid project name: '{project_name}' "
            "(contains control characters)"
        )
    reserved_candidate = project_name.rstrip(". ").upper()
    if reserved_candidate in WINDOWS_RESERVED_NAMES:
        raise ProjectCreationError(
            f"Invalid project name: '{project_name}' "
            "(reserved device name on Windows)"
        )


def ensure_scoped_dirs(base_dir: Path, prefix: str, names: list[str]) -> None:
    target_base = base_dir / prefix if prefix else base_dir
    if prefix:
        target_base.mkdir(parents=True, exist_ok=True)
    for name in names:
        (target_base / name).mkdir(parents=True, exist_ok=True)


def remove_existing_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    if path.is_dir():
        shutil.rmtree(path)
        return
    raise ProjectCreationError(f"Unsupported existing path type: '{path}'")


def create_project_structure(
    project_path: Path,
    has_external: bool,
    has_internal: bool,
    has_ad: bool,
    has_mobile: bool,
) -> None:
    (project_path / "Report").mkdir(parents=True, exist_ok=True)
    (project_path / "Screenshots").mkdir(parents=True, exist_ok=True)

    external_prefix = "External" if has_external and has_internal else ""
    internal_prefix = "Internal" if has_external and has_internal else ""

    if has_external:
        ensure_scoped_dirs(project_path, external_prefix, EXTERNAL_DIRS)

    if has_internal:
        ensure_scoped_dirs(project_path, internal_prefix, INTERNAL_DIRS)
        if has_ad:
            ensure_scoped_dirs(project_path, internal_prefix, AD_DIRS)

    if has_mobile:
        ensure_scoped_dirs(project_path, "Mobile", MOBILE_DIRS)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(add_help=False)
    parser.add_argument("project_name", nargs="?")
    parser.add_argument("-h", "--help", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    script_name = Path(sys.argv[0]).name if argv is None else "maketask"

    if args.help:
        print(usage_text(script_name))
        return 0

    if not args.project_name:
        print(usage_text(script_name), file=sys.stderr)
        return 1

    project_name = args.project_name

    try:
        validate_project_name(project_name)

        project_path = Path(project_name)
        print(f"[*] Creating pentest project: {project_name}")

        if project_path.exists() or project_path.is_symlink():
            if ask_yn(f"Directory '{project_name}' already exists. Overwrite it?"):
                remove_existing_path(project_path)
            else:
                raise ProjectCreationError(f"Directory '{project_name}' already exists")

        project_path.mkdir(parents=True, exist_ok=True)

        has_external = ask_yn("Is there External pentesting scope?")
        has_internal = ask_yn("Is there Internal pentesting scope?")
        has_ad = has_internal and ask_yn("Is this a Windows environment with Active Directory?")
        has_mobile = ask_yn("Is there Mobile pentesting scope?")

        create_project_structure(
            project_path=project_path,
            has_external=has_external,
            has_internal=has_internal,
            has_ad=has_ad,
            has_mobile=has_mobile,
        )
    except (OSError, ProjectCreationError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"[+] Project '{project_name}' successfully created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
