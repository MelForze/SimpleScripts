from __future__ import annotations

import base64
import hashlib
import tarfile
import zipfile
from pathlib import Path


PROJECT_NAME = "simplescripts"
VERSION = "0.1.0"
SUMMARY = "Collection of offensive-security and utility scripts from the SimpleScripts repository."
REQUIRES_PYTHON = ">=3.10"
LICENSE = "MIT"
AUTHOR = "MelForze"
DEPENDENCIES = [
    "ipwhois>=1.2.0",
    "passlib>=1.7.4",
    "pycryptodome>=3.20.0",
    "requests>=2.31.0",
    "rich>=13.7.0",
]
ROOT = Path(__file__).resolve().parent
DIST_INFO_DIRNAME = f"{PROJECT_NAME}-{VERSION}.dist-info"
SCRIPTS_DIRNAME = f"{PROJECT_NAME}-{VERSION}.data/scripts"
SDIST_DIRNAME = f"{PROJECT_NAME}-{VERSION}"
WHEEL_FILENAME = f"{PROJECT_NAME}-{VERSION}-py3-none-any.whl"

SCRIPT_SPECS = [
    ("AD/DBeaverdecrypt.py", "DBeaverdecrypt.py"),
    ("AD/DomainSid-Hex.py", "DomainSid-Hex.py"),
    ("AD/gpp_decrypt.py", "GPP_decrypt.py"),
    ("AD/LMHunter.py", "LMHunter.py"),
    ("AD/NTCreater.py", "NTCreater.py"),
    ("AD/PowerShellPayload.py", "PowerShellPayload.py"),
    ("AD/WeakPassHunter.py", "WeakPassHunter.py"),
    ("AD_PS/EncodeAssembly.ps1", "EncodeAssembly.ps1"),
    ("AD_PS/FindSPNAccounts.ps1", "FindSPNAccounts.ps1"),
    ("AD_PS/SearchRBCD.ps1", "SearchRBCD.ps1"),
    ("GetSomething/get_asn_by_domain.py", "get_asn_by_domain.py"),
    ("GetSomething/get_dns_by_file.py", "get_dns_by_file.py"),
    ("GetSomething/get_dns_by_ip.py", "get_dns_by_ip.py"),
    ("GetSomething/get_hash_by_opasswd.py", "get_hash_by_opasswd.py"),
    ("GetSomething/get_ip-white_by_file.py", "get_ip-white_by_file.py"),
    ("GetSomething/get_ip_by_file.py", "get_ip_by_file.py"),
    ("GetSomething/get_net_by_ip.py", "get_net_by_ip.py"),
    ("Hunters/CiphersHunter.py", "CiphersHunter.py"),
    ("Hunters/EOLHunter.py", "EOLHunter.py"),
    ("Hunters/HeadersHunter.py", "HeadersHunter.py"),
    ("Hunters/WildcardHunter.py", "WildcardHunter.py"),
    ("Collectors/KatanaScan.py", "KatanaScan.py"),
    ("Mobile/PoC_Janus.py", "PoC_Janus.py"),
    ("Mobile/get_deeplinks.py", "get_deeplinks.py"),
    ("Mobile/get_exported_activities.py", "get_exported_activities.py"),
    ("Scanners/masscan_to_nmap.py", "masscan_to_nmap.py"),
    ("Scanners/masscan_to_url.py", "masscan_to_url.py"),
    ("Scanners/nmap_to_ip-port.py", "nmap_to_ip-port.py"),
    ("Scanners/nmap_to_url.py", "nmap_to_url.py"),
    ("Assistants/maketask", "maketask"),
    ("Linux/pivot_access_init.sh", "pivot_access_init.sh"),
]
SCRIPT_FILES = list(dict.fromkeys(source for source, _ in SCRIPT_SPECS))
SDIST_FILES = [
    ".gitignore",
    "LICENSE",
    "README.md",
    "packaging_backend.py",
    "pyproject.toml",
    *SCRIPT_FILES,
]


def _metadata_text() -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {PROJECT_NAME}",
        f"Version: {VERSION}",
        f"Summary: {SUMMARY}",
        f"Author: {AUTHOR}",
        f"License: {LICENSE}",
        f"Requires-Python: {REQUIRES_PYTHON}",
        "Description-Content-Type: text/markdown",
    ]
    lines.extend(f"Requires-Dist: {dependency}" for dependency in DEPENDENCIES)
    lines.append("")
    lines.append(readme)
    return "\n".join(lines)


def _wheel_text() -> str:
    return "\n".join(
        [
            "Wheel-Version: 1.0",
            "Generator: simplescripts.packaging_backend",
            "Root-Is-Purelib: true",
            "Tag: py3-none-any",
            "",
        ]
    )


def _record_row(path: str, data: bytes) -> tuple[str, str, str]:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return path, f"sha256={encoded}", str(len(data))


def _zip_info(arcname: str, executable: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(arcname)
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = 0o755 if executable else 0o644
    info.external_attr = mode << 16
    return info


def _dist_info_contents() -> dict[str, bytes]:
    return {
        f"{DIST_INFO_DIRNAME}/METADATA": _metadata_text().encode("utf-8"),
        f"{DIST_INFO_DIRNAME}/WHEEL": _wheel_text().encode("utf-8"),
    }


def _build_record(rows: list[tuple[str, str, str]]) -> bytes:
    output = []
    for row in rows:
        output.append(",".join(row))
    output.append(f"{DIST_INFO_DIRNAME}/RECORD,,")
    return ("\n".join(output) + "\n").encode("utf-8")


def _validate_script_sources() -> None:
    missing_sources = [
        source for source in SCRIPT_FILES if not (ROOT / source).is_file()
    ]
    if missing_sources:
        raise FileNotFoundError(
            "Missing script sources for packaging: "
            + ", ".join(sorted(missing_sources))
        )


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    metadata_root = Path(metadata_directory)
    dist_info = metadata_root / DIST_INFO_DIRNAME
    dist_info.mkdir(parents=True, exist_ok=True)
    contents = _dist_info_contents()
    for relpath, data in contents.items():
        (metadata_root / relpath).write_bytes(data)
    return DIST_INFO_DIRNAME


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _validate_script_sources()
    wheel_dir = Path(wheel_directory)
    wheel_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = wheel_dir / WHEEL_FILENAME

    rows: list[tuple[str, str, str]] = []
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for relpath, data in _dist_info_contents().items():
            archive.writestr(_zip_info(relpath, executable=False), data)
            rows.append(_record_row(relpath, data))

        for source, install_name in SCRIPT_SPECS:
            source_path = ROOT / source
            data = source_path.read_bytes()
            arcname = f"{SCRIPTS_DIRNAME}/{install_name}"
            archive.writestr(_zip_info(arcname, executable=True), data)
            rows.append(_record_row(arcname, data))

        record_data = _build_record(rows)
        archive.writestr(
            _zip_info(f"{DIST_INFO_DIRNAME}/RECORD", executable=False),
            record_data,
        )

    return wheel_path.name


def build_sdist(sdist_directory, config_settings=None):
    _validate_script_sources()
    sdist_dir = Path(sdist_directory)
    sdist_dir.mkdir(parents=True, exist_ok=True)
    sdist_path = sdist_dir / f"{SDIST_DIRNAME}.tar.gz"

    with tarfile.open(sdist_path, "w:gz") as archive:
        for relpath in SDIST_FILES:
            source_path = ROOT / relpath
            archive.add(source_path, arcname=f"{SDIST_DIRNAME}/{relpath}")

    return sdist_path.name
