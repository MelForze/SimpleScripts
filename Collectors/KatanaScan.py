#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path
import argparse

# --- Configuration for crawl modes ---
FOLDERS = {
    'allurls': [],
    'files': ['-f', 'ufile'],
    'paths': ['-f', 'udir'],
}

KATANA_BASE_OPTS = [
    '-d', '5',
    '-crawl-scope', None,
    '-js-crawl', '-jsluice',
    '-crawl-duration', '15m',
    '-known-files', 'all',
    '-disable-redirects',
    '-c', '150',
    '-p', '1',
    '-silent'
]

def sanitize_filename(url: str) -> str:
    """Convert URL into a safe filename by replacing special characters."""
    return (url.replace('https://', 'https_')
               .replace('http://', 'http_')
               .replace('.', '_')
               .replace(':', '_')
               .replace('/', '_'))

def run_katana(url: str, out_dir: Path, extra_opts: list[str], use_headless: bool) -> None:
    """
    Run katana on a URL in a specific mode, sort the output,
    prepend URL for 'paths' mode, and clean up temp files.
    """
    safe = sanitize_filename(url)
    temp = out_dir / f"{safe}_active.txt"
    sorted_tmp = out_dir / f"{safe}_sorted.txt"
    final = out_dir / f"{safe}_Katana.txt"

    print(f"[+] {out_dir.name}: crawling {url}")

    cmd = ['katana', '-u', url] + KATANA_BASE_OPTS.copy()
    cmd[cmd.index('-crawl-scope') + 1] = url
    if use_headless:
        cmd.append('-headless')
    cmd += extra_opts

    try:
        with temp.open('w') as t:
            subprocess.run(cmd, stdout=t, stderr=subprocess.DEVNULL, check=True)

        subprocess.run(['sort', '-u', str(temp), '-o', str(sorted_tmp)], check=True)

        if out_dir.name == 'paths':
            with final.open('w') as out:
                out.write(url + "\n")
                out.write(sorted_tmp.read_text())
        else:
            sorted_tmp.replace(final)

    except subprocess.CalledProcessError as e:
        print(f"[!] Error in {out_dir.name} for {url}: {e}")
    finally:
        for fp in (temp, sorted_tmp):
            if fp.exists():
                fp.unlink()

def main():
    """Main: parse args, create dirs based on selection, run katana per mode."""
    parser = argparse.ArgumentParser(
        description="Run katana in selected modes: allurls, files, paths."
    )
    parser.add_argument('url_file', type=Path, help="File with URLs (one per line)")
    parser.add_argument('-b', '--browser', action='store_true',
                        help="Enable headless browsing mode")
    parser.add_argument('-all', '--all', action='store_true',
                        help="Crawl everything (allurls mode)")
    parser.add_argument('-file', '--file', action='store_true',
                        help="Crawl only files (files mode)")
    parser.add_argument('-path', '--path', action='store_true',
                        help="Crawl only paths (paths mode)")

    args = parser.parse_args()

    if not args.url_file.is_file():
        print(f"[!] URL file not found: {args.url_file}")
        sys.exit(1)

    # Determine selected modes
    selected = []
    if args.all:
        selected.append('allurls')
    if args.file:
        selected.append('files')
    if args.path:
        selected.append('paths')
    if not selected:
        print("[!] Please specify at least one of --all, --file, or --path")
        sys.exit(1)

    urls = [u.strip() for u in args.url_file.read_text().splitlines() if u.strip()]
    if not urls:
        print("[!] No URLs to process.")
        sys.exit(1)

    # Create only necessary directories
    for mode in selected:
        Path(mode).mkdir(exist_ok=True)

    # Run katana in each selected mode
    for url in urls:
        for mode in selected:
            run_katana(url, Path(mode), FOLDERS[mode], use_headless=args.browser)

if __name__ == '__main__':
    main()