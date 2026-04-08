#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
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
    proxy: str | None = None,
    headers: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """Run katana for one URL/mode pair and return deduplicated result lines."""
    safe = sanitize_filename(url)
    temp = out_dir / f"{safe}_active.txt"

    print(f"[+] {out_dir.name}: crawling {url}")

    cmd = build_katana_command(
        url=url,
        use_headless=use_headless,
        proxy=proxy,
        headers=headers,
        extra_opts=extra_opts,
    )

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
    proxy: str | None = None,
    headers: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """Run katana for one URL in JSONL mode and return raw non-empty lines."""
    print(f"[+] dast: crawling {url}")

    cmd = build_katana_command(
        url=url,
        use_headless=use_headless,
        proxy=proxy,
        headers=headers,
        is_dast=True,
    )

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


def build_katana_command(
    url: str,
    use_headless: bool,
    proxy: str | None = None,
    headers: list[str] | None = None,
    extra_opts: list[str] | None = None,
    is_dast: bool = False,
) -> list[str]:
    """Build a katana command with shared options for normal and DAST runs."""
    cmd = ["katana", "-u", url] + KATANA_BASE_OPTS.copy()
    cmd[cmd.index("-crawl-scope") + 1] = url

    if proxy:
        cmd += ["-proxy", proxy]

    for header in headers or []:
        cmd += ["-H", header]

    if is_dast:
        cmd += ["-jsonl", "-aff", "-iqp"]

    if use_headless:
        cmd.append("-headless")

    if extra_opts:
        cmd += extra_opts

    return cmd


def has_same_origin(candidate_url: str, expected_origin: str) -> bool:
    """Check whether candidate URL belongs to the expected normalized origin."""
    try:
        return origin_from_url(candidate_url) == expected_origin
    except ValueError:
        return False


def filter_lines_to_origin(lines: list[str], expected_origin: str) -> list[str]:
    """Filter plain URL lines to the expected origin."""
    return [line for line in lines if has_same_origin(line, expected_origin)]


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
        "--dast-output",
        type=Path,
        default=None,
        help="Output file for --dast mode. Default: <output-dir>/katana-dast.jsonl",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Maximum number of concurrent katana processes. Default: 4",
    )
    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="Proxy to pass to katana -proxy, for example: http://127.0.0.1:8080",
    )
    parser.add_argument(
        "--header",
        dest="headers",
        action="append",
        help='Additional request header, repeat as needed. Example: --header "Authorization: Bearer XXX"',
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
    args.output_dir = Path(str(args.output_dir)).expanduser()
    if args.dast_output is not None:
        args.dast_output = Path(str(args.dast_output)).expanduser()

    if not args.input.is_file():
        print(f"[!] URL file not found: {args.input}", file=sys.stderr)
        return 1

    if args.workers < 1:
        print("[!] --workers must be at least 1.", file=sys.stderr)
        return 1

    if args.dast and args.modes:
        print("[!] --dast cannot be combined with -m/--mode.", file=sys.stderr)
        return 1

    if args.dast_output is not None and not args.dast:
        print("[!] --dast-output can only be used with --dast.", file=sys.stderr)
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
        if args.dast_output is None:
            output_root.mkdir(parents=True, exist_ok=True)
            dast_output = output_root / "katana-dast.jsonl"
        else:
            dast_output = args.dast_output

        dast_output.parent.mkdir(parents=True, exist_ok=True)
        failures: list[str] = []
        indexed_results: dict[int, list[str]] = {}

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_item = {
                executor.submit(
                    run_katana_dast,
                    url=url,
                    use_headless=args.browser,
                    proxy=args.proxy,
                    headers=args.headers,
                ): (idx, url)
                for idx, url in enumerate(urls)
            }

            for future in as_completed(future_to_item):
                idx, url = future_to_item[future]
                success, lines = future.result()
                if not success:
                    failures.append(url)
                    continue
                indexed_results[idx] = lines

        dast_lines: list[str] = []
        for idx in range(len(urls)):
            dast_lines.extend(indexed_results.get(idx, []))

        final_lines = dedupe_preserve_order(dast_lines)
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
    tasks: list[tuple[str, str, str, Path, list[str]]] = []
    group_seed_urls: dict[tuple[str, str], list[str]] = {}
    group_mode_dirs: dict[tuple[str, str], Path] = {}
    group_remaining: dict[tuple[str, str], int] = {}
    group_results: dict[tuple[str, str], list[list[str]]] = {}

    for mode in selected_modes:
        mode_dir = output_root / str(MODE_CONFIG[mode]["directory"])
        mode_dir.mkdir(parents=True, exist_ok=True)

    for origin, seed_urls in grouped_urls.items():
        for mode in selected_modes:
            mode_dir = output_root / str(MODE_CONFIG[mode]["directory"])
            extra_opts = list(MODE_CONFIG[mode]["extra_opts"])
            group_key = (mode, origin)
            group_seed_urls[group_key] = seed_urls
            group_mode_dirs[group_key] = mode_dir
            group_remaining[group_key] = len(seed_urls)
            group_results[group_key] = []
            for url in seed_urls:
                tasks.append((mode, origin, url, mode_dir, extra_opts))

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_item = {
            executor.submit(
                run_katana,
                url=url,
                out_dir=mode_dir,
                extra_opts=extra_opts,
                use_headless=args.browser,
                proxy=args.proxy,
                headers=args.headers,
            ): (mode, origin, url)
            for mode, origin, url, mode_dir, extra_opts in tasks
        }

        for future in as_completed(future_to_item):
            mode, origin, url = future_to_item[future]
            success, lines = future.result()
            group_key = (mode, origin)
            if not success:
                failures.append((url, mode))
            else:
                if mode == "paths":
                    lines = filter_lines_to_origin(lines, origin)
                group_results[group_key].append(lines)

            group_remaining[group_key] -= 1
            if group_remaining[group_key] == 0:
                seed_results = group_results[group_key]
                if seed_results:
                    merged_lines = merge_origin_results(
                        mode,
                        group_seed_urls[group_key],
                        seed_results,
                    )
                    write_origin_results(origin, group_mode_dirs[group_key], merged_lines)

    if failures:
        print(f"[!] Katana failed for {len(failures)} target/mode combinations.", file=sys.stderr)
        for url, mode in failures:
            print(f"    - {url} ({mode})", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
