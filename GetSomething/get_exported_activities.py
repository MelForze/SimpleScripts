#!/usr/bin/env python3
"""
Скрипт: list_exported_activities.py
Использование:
    python get_exported_activities.py /path/to/AndroidManifest.xml
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# URI пространства имён android
ANDROID_NS = "http://schemas.android.com/apk/res/android"
NAME_ATTR = f"{{{ANDROID_NS}}}name"
EXPORTED_ATTR = f"{{{ANDROID_NS}}}exported"


def get_exported_activities(manifest_path: Path) -> list[str]:
    """Возвращает список имён активити/алиасов с android:exported="true"."""
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    # <application> может быть не единственным уровнем,
    # поэтому используем find в случае неймспейсов
    application = root.find("application")
    if application is None:
        raise ValueError("В манифесте не найден тег <application>.")

    exported = []

    # Ищем и <activity>, и <activity-alias>
    for tag in ("activity", "activity-alias"):
        for elem in application.findall(f".//{tag}"):
            if elem.attrib.get(EXPORTED_ATTR) == "true":
                name = elem.attrib.get(NAME_ATTR)
                if name:
                    exported.append(name)

    return exported


def main() -> None:
    if len(sys.argv) != 2:
        script = Path(sys.argv[0]).name
        print(f"Использование: python {script} /path/to/AndroidManifest.xml")
        sys.exit(1)

    manifest_file = Path(sys.argv[1])
    if not manifest_file.is_file():
        print(f"Файл {manifest_file} не найден.")
        sys.exit(1)

    for activity in get_exported_activities(manifest_file):
        print(activity)


if __name__ == "__main__":
    main()
