#!/usr/bin/env python3

import argparse
import shutil
import sys
from pathlib import Path


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


def die(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def ask_yn(prompt: str) -> bool:
    while True:
        answer = input(f"{prompt} (Y/N): ").strip()
        if answer.lower() == "y":
            return True
        if answer.lower() == "n":
            return False
        print("Please enter Y or N.")


def validate_project_name(project_name: str) -> None:
    if (
        not project_name
        or project_name in {".", "..", "/"}
        or "/" in project_name
    ):
        die(
            f"Invalid project name: '{project_name}' "
            "(must be a simple folder name without slashes)"
        )


def ensure_scoped_dirs(base_dir: Path, prefix: str, names: list[str]) -> None:
    target_base = base_dir / prefix if prefix else base_dir
    if prefix:
        target_base.mkdir(parents=True, exist_ok=True)
    for name in names:
        (target_base / name).mkdir(parents=True, exist_ok=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
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
    validate_project_name(project_name)

    project_path = Path(project_name)
    print(f"[*] Creating pentest project: {project_name}")

    if project_path.exists():
        if ask_yn(f"Directory '{project_name}' already exists. Overwrite it?"):
            if project_path.is_dir():
                shutil.rmtree(project_path)
            else:
                project_path.unlink()
        else:
            die(f"Directory '{project_name}' already exists")

    project_path.mkdir(parents=True, exist_ok=True)
    (project_path / "Report").mkdir(parents=True, exist_ok=True)
    (project_path / "Screenshots").mkdir(parents=True, exist_ok=True)

    has_external = ask_yn("Is there External pentesting scope?")
    has_internal = ask_yn("Is there Internal pentesting scope?")
    has_ad = has_internal and ask_yn("Is this a Windows environment with Active Directory?")
    has_mobile = ask_yn("Is there Mobile pentesting scope?")

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

    print(f"[+] Project '{project_name}' successfully created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
