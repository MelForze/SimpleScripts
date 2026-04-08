#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


MODE_CONFIG: dict[str, dict[str, list[str] | str]] = {
    "all": {"directory": "allurls", "extra_opts": []},
    "files": {"directory": "files", "extra_opts": ["-f", "ufile"]},
    "paths": {"directory": "paths", "extra_opts": ["-f", "udir"]},
}
VISIBLE_MODES = ("all", "files", "paths", "everything")
SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
HTTP_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

KATANA_BASE_OPTS = [
    "-d",
    "5",
    "-crawl-scope",
    None,
    "-js-crawl",
    "-jsluice",
    "-crawl-duration",
    "15m",
    "-known-files",
    "all",
    "-disable-redirects",
    "-c",
    "150",
    "-p",
    "1",
    "-silent",
]


def create_argument_parser(*args, **kwargs) -> argparse.ArgumentParser:
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def normalize_url(url: str) -> str:
    """Normalize an HTTP(S) URL for crawling and deduplication."""
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("unsupported scheme")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("missing hostname")

    hostname = hostname.lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"

    path = re.sub(r"/+", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
        if not path:
            path = "/"

    return urlunsplit((scheme, netloc, path, "", ""))


def sanitize_filename(url: str) -> str:
    """Convert a normalized URL into a deterministic filesystem-safe filename."""
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)

    hostname = (parsed.hostname or "unknown").replace(":", "_")
    port_suffix = f"_{parsed.port}" if parsed.port else ""
    raw_path = parsed.path.strip("/") or "root"
    safe_path = SAFE_FILENAME_RE.sub("_", raw_path).strip("._-") or "root"
    safe_base = f"{parsed.scheme}_{hostname}{port_suffix}_{safe_path}"
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:10]
    return f"{safe_base}_{digest}"


def origin_from_url(url: str) -> str:
    """Return a normalized origin URL."""
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname or ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, "/", "", ""))


def sanitize_origin_filename(origin: str) -> str:
    """Convert a normalized origin URL into a stable output filename base."""
    parsed = urlsplit(origin)
    hostname = (parsed.hostname or "unknown").replace(":", "_")
    port_suffix = f"_{parsed.port}" if parsed.port else ""
    safe_host = SAFE_FILENAME_RE.sub("_", hostname).strip("._-") or "unknown"
    return f"{parsed.scheme}_{safe_host}{port_suffix}"


def read_input_urls(url_file: Path) -> list[str]:
    """Read, normalize, and deduplicate URLs from an input file."""
    urls: list[str] = []
    seen: set[str] = set()

    for line_number, raw_line in enumerate(
        url_file.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            normalized = normalize_url(line)
        except ValueError as exc:
            print(
                f"[!] Skipping invalid URL on line {line_number}: {line} ({exc})",
                file=sys.stderr,
            )
            continue

        if normalized in seen:
            continue

        seen.add(normalized)
        urls.append(normalized)

    return urls


def group_urls_by_origin(urls: list[str]) -> dict[str, list[str]]:
    """Group seed URLs by normalized origin while preserving input order."""
    grouped: dict[str, list[str]] = {}
    for url in urls:
        origin = origin_from_url(url)
        grouped.setdefault(origin, []).append(url)
    return grouped


def sort_unique_lines(path: Path) -> list[str]:
    """Return sorted unique non-empty lines from a file."""
    lines = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    return sorted(lines)


def run_katana(
    url: str,
    out_dir: Path,
    extra_opts: list[str],
    use_headless: bool,
) -> tuple[bool, list[str]]:
    """Run katana for one URL/mode pair and return deduplicated result lines."""
    safe = sanitize_filename(url)
    temp = out_dir / f"{safe}_active.txt"

    print(f"[+] {out_dir.name}: crawling {url}")

    cmd = ["katana", "-u", url] + KATANA_BASE_OPTS.copy()
    cmd[cmd.index("-crawl-scope") + 1] = url
    if use_headless:
        cmd.append("-headless")
    cmd += extra_opts

    try:
        with temp.open("w", encoding="utf-8") as temp_handle:
            subprocess.run(cmd, stdout=temp_handle, stderr=subprocess.DEVNULL, check=True)

        return True, sort_unique_lines(temp)
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"[!] Error in {out_dir.name} for {url}: {exc}", file=sys.stderr)
        return False, []
    finally:
        if temp.exists():
            temp.unlink()


def run_katana_dast(
    url: str,
    use_headless: bool,
) -> tuple[bool, list[str]]:
    """Run katana for one URL in JSONL mode and return raw non-empty lines."""
    print(f"[+] dast: crawling {url}")

    cmd = ["katana", "-u", url] + KATANA_BASE_OPTS.copy()
    cmd[cmd.index("-crawl-scope") + 1] = url
    cmd += ["-jsonl", "-aff", "-iqp"]
    if use_headless:
        cmd.append("-headless")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"[!] Error in dast for {url}: {exc}", file=sys.stderr)
        return False, []

    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    return True, lines


def dedupe_preserve_order(lines: list[str]) -> list[str]:
    """Return deduplicated lines while preserving first-seen order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        ordered.append(line)
    return ordered


def find_first_url(value) -> str | None:
    """Recursively find the first URL-like value in a JSON-compatible object."""
    if isinstance(value, str):
        candidate = value.strip()
        if candidate.startswith("http://") or candidate.startswith("https://"):
            return candidate
        match = HTTP_URL_RE.search(candidate)
        return match.group(0) if match else None

    if isinstance(value, dict):
        for nested in value.values():
            found = find_first_url(nested)
            if found:
                return found
        return None

    if isinstance(value, list):
        for nested in value:
            found = find_first_url(nested)
            if found:
                return found
        return None

    return None


def has_same_origin(candidate_url: str, expected_origin: str) -> bool:
    """Check whether candidate URL belongs to the expected normalized origin."""
    try:
        return origin_from_url(candidate_url) == expected_origin
    except ValueError:
        return False


def filter_lines_to_origin(lines: list[str], expected_origin: str) -> list[str]:
    """Filter plain URL lines to the expected origin."""
    return [line for line in lines if has_same_origin(line, expected_origin)]


def filter_dast_lines_to_origin(lines: list[str], expected_origin: str) -> list[str]:
    """Filter raw katana JSONL lines by the first URL found in each JSON record."""
    filtered: list[str] = []
    for line in lines:
        candidate_url: str | None = None
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            payload = None

        if payload is not None:
            candidate_url = find_first_url(payload)
        if not candidate_url:
            fallback = HTTP_URL_RE.search(line)
            if fallback:
                candidate_url = fallback.group(0)

        if candidate_url and has_same_origin(candidate_url, expected_origin):
            filtered.append(line)
    return filtered


def merge_origin_results(mode: str, seed_urls: list[str], seed_results: list[list[str]]) -> list[str]:
    """Merge multiple katana runs for a single origin into one deduplicated output."""
    merged: set[str] = set()
    for lines in seed_results:
        merged.update(line for line in lines if line)

    if mode == "paths":
        merged.update(seed_urls)

    return sorted(merged)


def write_origin_results(origin: str, out_dir: Path, lines: list[str]) -> Path:
    """Write merged origin results into a single output file."""
    final = out_dir / f"{sanitize_origin_filename(origin)}_Katana.txt"
    final.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return final


def parse_args(argv=None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = create_argument_parser(
        description=(
            "Run katana in selected modes (all/files/paths) or in --dast mode "
            "that writes a single katana-dast.jsonl file."
        )
    )
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        required=True,
        help="File with URLs (one per line).",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Directory where per-mode output folders will be created. Default: current directory.",
    )
    parser.add_argument(
        "-m",
        "--mode",
        dest="modes",
        action="append",
        choices=VISIBLE_MODES,
        help=(
            "Crawl mode to run. Use 'everything' for all, files, and paths. "
            "Repeat the flag if needed. Required unless --dast is used."
        ),
    )
    parser.add_argument(
        "--dast",
        action="store_true",
        help="Run DAST mode and write a single katana-dast.jsonl file. Cannot be used with -m/--mode.",
    )
    parser.add_argument(
        "--same-origin-only",
        action="store_true",
        help="Keep only results that match the origin of each input URL.",
    )
    parser.add_argument(
        "-b",
        "--browser",
        action="store_true",
        help="Enable headless browsing mode.",
    )

    return parser.parse_args(argv)


def resolve_selected_modes(args: argparse.Namespace) -> list[str]:
    """Resolve requested modes from the CLI flags."""
    selected: list[str] = []

    for mode in args.modes or []:
        if mode == "everything":
            for expanded_mode in MODE_CONFIG:
                if expanded_mode not in selected:
                    selected.append(expanded_mode)
            continue

        if mode not in selected:
            selected.append(mode)

    return selected


def main(argv=None) -> int:
    args = parse_args(argv)

    if not args.input.is_file():
        print(f"[!] URL file not found: {args.input}", file=sys.stderr)
        return 1

    if args.dast and args.modes:
        print("[!] --dast cannot be combined with -m/--mode.", file=sys.stderr)
        return 1

    selected_modes: list[str] = []
    if not args.dast:
        selected_modes = resolve_selected_modes(args)
        if not selected_modes:
            print("[!] Please specify at least one crawl mode with -m/--mode.", file=sys.stderr)
            return 1

    try:
        urls = read_input_urls(args.input)
    except OSError as exc:
        print(f"[!] Failed to read URL file {args.input}: {exc}", file=sys.stderr)
        return 1

    if not urls:
        print("[!] No valid URLs to process.", file=sys.stderr)
        return 1

    output_root = args.output_dir

    if args.dast:
        output_root.mkdir(parents=True, exist_ok=True)
        dast_lines: list[str] = []
        failures: list[str] = []

        for url in urls:
            success, lines = run_katana_dast(
                url=url,
                use_headless=args.browser,
            )
            if not success:
                failures.append(url)
                continue
            if args.same_origin_only:
                lines = filter_dast_lines_to_origin(lines, origin_from_url(url))
            dast_lines.extend(lines)

        final_lines = dedupe_preserve_order(dast_lines)
        dast_output = output_root / "katana-dast.jsonl"
        dast_output.write_text(
            "\n".join(final_lines) + ("\n" if final_lines else ""),
            encoding="utf-8",
        )

        if failures:
            print(f"[!] Katana failed for {len(failures)} target(s) in dast mode.", file=sys.stderr)
            for url in failures:
                print(f"    - {url}", file=sys.stderr)
            return 1

        return 0

    failures: list[tuple[str, str]] = []
    grouped_urls = group_urls_by_origin(urls)

    for mode in selected_modes:
        mode_dir = output_root / str(MODE_CONFIG[mode]["directory"])
        mode_dir.mkdir(parents=True, exist_ok=True)

    for origin, seed_urls in grouped_urls.items():
        for mode in selected_modes:
            mode_dir = output_root / str(MODE_CONFIG[mode]["directory"])
            extra_opts = list(MODE_CONFIG[mode]["extra_opts"])
            seed_results: list[list[str]] = []

            for url in seed_urls:
                success, lines = run_katana(
                    url=url,
                    out_dir=mode_dir,
                    extra_opts=extra_opts,
                    use_headless=args.browser,
                )
                if not success:
                    failures.append((url, mode))
                    continue
                lines = filter_lines_to_origin(lines, origin)
                seed_results.append(lines)

            if seed_results:
                merged_lines = merge_origin_results(mode, seed_urls, seed_results)
                write_origin_results(origin, mode_dir, merged_lines)

    if failures:
        print(f"[!] Katana failed for {len(failures)} target/mode combinations.", file=sys.stderr)
        for url, mode in failures:
            print(f"    - {url} ({mode})", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
