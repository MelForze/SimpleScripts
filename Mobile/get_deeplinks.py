#!/usr/bin/env python3
"""deeplink_analyzer.py  – v1.2

Extracts as many deep links as possible from AndroidManifest.xml.
Additional support includes:
* scanning <activity-alias>, <service>, <receiver>, and <provider>
* handling http/https intent filters without a host (output `scheme://`)
* showing the component that owns the link (type + name) in detailed output
"""

from __future__ import annotations

import argparse
import logging
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from itertools import product
from pathlib import Path
from typing import Final, Iterable, Sequence

ANDROID_NS: Final = "http://schemas.android.com/apk/res/android"
NS = {"android": ANDROID_NS}
LOGGER = logging.getLogger("deeplink_analyzer")
COMPONENT_TAGS: Final[Sequence[str]] = (
    "activity",
    "activity-alias",
    "service",
    "receiver",
    "provider",
)


def _auto() -> frozenset[str]:
    return frozenset()


@dataclass(frozen=True, slots=True)
class IntentFilterData:
    schemes: frozenset[str] = field(default_factory=_auto)
    hosts: frozenset[str] = field(default_factory=_auto)
    paths: frozenset[str] = field(default_factory=_auto)


@dataclass(frozen=True, slots=True)
class ComponentDeepLinks:
    """Deep links collected from a single component (activity, service, ...)."""

    tag: str
    name: str
    links: frozenset[str]


class DeepLinkGenerator:
    HTTP_SCHEMES = {"http", "https"}

    def __init__(self, include_paths: bool = False) -> None:
        self._format_path = (
            self._format_full_path if include_paths else self._format_root_only
        )

    def collect(self, intent: ET.Element) -> IntentFilterData:
        schemes, hosts, paths = set[str](), set[str](), set[str]()
        for data in intent.findall("data"):
            if s := (data.get(f"{{{ANDROID_NS}}}scheme") or "").lower():
                schemes.add(s)
            if h := data.get(f"{{{ANDROID_NS}}}host"):
                hosts.add(h.strip())
            if p := self._extract_path(data):
                paths.add(p)
        return IntentFilterData(frozenset(schemes), frozenset(hosts), frozenset(paths))

    def generate(self, data: IntentFilterData) -> frozenset[str]:
        links: set[str] = set()
        for scheme in data.schemes:
            hosts = self._valid_hosts(scheme, data.hosts)
            paths = data.paths or {""}
            for host, path in product(hosts or [None], paths):
                links.add(self._build(scheme, host, path))
        LOGGER.debug("%d links for schemes %s", len(links), ",".join(data.schemes))
        return frozenset(links)

    def _extract_path(self, node: ET.Element) -> str | None:
        for attr in ("path", "pathPrefix", "pathPattern"):
            if val := node.get(f"{{{ANDROID_NS}}}{attr}"):
                return self._format_path(val)
        return None

    def _valid_hosts(self, scheme: str, hosts: frozenset[str]) -> frozenset[str]:
        if scheme in self.HTTP_SCHEMES:
            return hosts or frozenset({""})
        return hosts or frozenset({""})

    @staticmethod
    def _build(scheme: str, host: str | None, path: str) -> str:
        host_part = host or ""
        base = f"{scheme}://{host_part}"
        if path:
            return f"{base}{path}"
        return base

    @staticmethod
    def _format_root_only(_: str) -> str:
        return ""

    @staticmethod
    def _format_full_path(path: str) -> str:
        return f"/{path.lstrip('/')}" if path.strip("/") else ""


class AndroidManifestParser:
    def __init__(self, file: Path):
        if not file.exists():
            raise FileNotFoundError(file)
        try:
            self._root = ET.parse(file).getroot()
        except ET.ParseError as exc:
            raise ET.ParseError(f"Invalid XML: {exc}") from exc

    def components(self) -> Iterable[ET.Element]:
        for tag in COMPONENT_TAGS:
            yield from self._root.findall(f".//{tag}")


class DeepLinkAnalyzer:
    def __init__(self, manifest: Path, include_paths: bool = False):
        self._parser = AndroidManifestParser(manifest)
        self._gen = DeepLinkGenerator(include_paths)

    def analyze(self) -> list[ComponentDeepLinks]:
        results: list[ComponentDeepLinks] = []
        for comp in self._parser.components():
            name = comp.get(f"{{{ANDROID_NS}}}name") or "<anonymous>"
            tag = comp.tag
            links: set[str] = set()
            for intent in comp.findall("intent-filter"):
                data = self._gen.collect(intent)
                links.update(self._gen.generate(data))
            if links:
                results.append(ComponentDeepLinks(tag, name, frozenset(links)))
        return results


def _arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deeplink-analyzer",
        description="Extract deep links from AndroidManifest.xml",
    )
    parser.add_argument("manifest", type=Path, help="Path to AndroidManifest.xml")
    parser.add_argument("-p", "--paths", action="store_true", help="Include paths in output")
    parser.add_argument("-l", "--list", action="store_true", help="List only unique links")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


def _setup_log(debug: bool):
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )


def _print_links_only(results: list[ComponentDeepLinks]):
    unique = {link for entry in results for link in entry.links}
    for link in sorted(unique):
        print(link)


def _print_report(results: list[ComponentDeepLinks]):
    for entry in results:
        print(f"\n[{entry.tag}] {entry.name}")
        for index, link in enumerate(sorted(entry.links), 1):
            print(f"{index:>3}. {link}")


def main(argv: list[str] | None = None):
    args = _arg_parser().parse_args(argv)
    _setup_log(args.debug)

    try:
        analyzer = DeepLinkAnalyzer(args.manifest, args.paths)
        results = analyzer.analyze()
        if args.list:
            _print_links_only(results)
        else:
            _print_report(results)
    except (FileNotFoundError, ET.ParseError, OSError, ValueError) as exc:
        LOGGER.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
