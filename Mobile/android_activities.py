#!/usr/bin/env python3
"""List exported Android activities and activity aliases from AndroidManifest.xml."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def create_argument_parser(*args, **kwargs) -> argparse.ArgumentParser:
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


ANDROID_NS = "http://schemas.android.com/apk/res/android"
NAME_ATTR = f"{{{ANDROID_NS}}}name"
EXPORTED_ATTR = f"{{{ANDROID_NS}}}exported"


def is_exported_component(element: ET.Element) -> bool:
    """Return whether an activity-like component is exported."""
    exported_attr = element.attrib.get(EXPORTED_ATTR)
    if exported_attr == "true":
        return True
    if exported_attr == "false":
        return False
    return element.find("intent-filter") is not None


def get_exported_activities(manifest_path: Path) -> list[str]:
    """Return exported activity/activity-alias names from a manifest."""
    try:
        tree = ET.parse(manifest_path)
    except ET.ParseError as exc:
        raise ET.ParseError(f"Invalid XML: {exc}") from exc

    root = tree.getroot()
    application = root.find("application")
    if application is None:
        raise ValueError("Missing <application> tag in manifest.")

    exported: list[str] = []
    for tag in ("activity", "activity-alias"):
        for element in application.findall(f".//{tag}"):
            if not is_exported_component(element):
                continue
            name = element.attrib.get(NAME_ATTR)
            if name:
                exported.append(name)
    return exported


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = create_argument_parser(
        prog="get_exported_activities.py",
        description="List exported activities and activity aliases from AndroidManifest.xml.",
    )
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        help="Path to AndroidManifest.xml.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.input is None:
        print("Error: Please provide -i/--input.", file=sys.stderr)
        return 1
    if not args.input.is_file():
        print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
        return 1

    try:
        activities = get_exported_activities(args.input)
    except (ET.ParseError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    for activity in activities:
        print(activity)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
