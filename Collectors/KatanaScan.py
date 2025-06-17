#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

# --- Configuration ---
# Three folders: allurls (all resources), files (file URLs), paths (directories)
FOLDERS = {
    'allurls': [],             # collect everything
    'files': ['-f', 'ufile'],  # collect files
    'paths': ['-f', 'udir'],   # collect directories + prepend URL
}

# Base options for katana; '-crawl-scope' will be substituted per URL
KATANA_BASE_OPTS = [
    '-d', '5',
    '-crawl-scope', None,
    '-js-crawl', '-jsluice',
    '-crawl-duration', '15m',
    '-known-files', 'all',
    '-disable-redirects',
    '-headless',
    '-c', '150',
    '-p', '1',
    '-silent'
]

def sanitize_filename(url: str) -> str:
    """
    Convert a URL into a safe filename by replacing special characters.
    """
    return (url.replace('https://', 'https_')
               .replace('http://', 'http_')
               .replace('.', '_')
               .replace(':', '_')
               .replace('/', '_'))

def run_katana(url: str, out_dir: Path, extra_opts: list[str]) -> None:
    safe = sanitize_filename(url)
    temp_file = out_dir / f"{safe}_active.txt"
    sorted_file = out_dir / f"{safe}_sorted.txt"
    final_file = out_dir / f"{safe}_Katana.txt"

    print(f"[+] {out_dir.name}: processing {url}")

    cmd = ['katana', '-u', url] + KATANA_BASE_OPTS.copy()
    cmd[cmd.index('-crawl-scope') + 1] = url
    cmd += extra_opts

    try:
        with temp_file.open('w') as tmpf:
            subprocess.run(cmd, stdout=tmpf, stderr=subprocess.DEVNULL, check=True)

        # Sort and dedupe only katana output
        subprocess.run(['sort', '-u', str(temp_file), '-o', str(sorted_file)], check=True)

        # For paths: prepend URL before sorted content
        if out_dir.name == 'paths':
            with final_file.open('w') as outf:
                outf.write(url + "\n")
                outf.write(sorted_file.read_text())
        else:
            # Move sorted to final
            sorted_file.rename(final_file)

    except subprocess.CalledProcessError as e:
        print(f"[!] Error processing {url} in {out_dir.name}: {e}")
    finally:
        for tmp in (temp_file, sorted_file):
            if tmp.exists():
                tmp.unlink()

def main():
    """
    Main entry point: parse arguments, create folders, read URLs, and process them.
    """
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file_with_urls>")
        sys.exit(1)

    url_file = Path(sys.argv[1])
    if not url_file.is_file():
        print(f"[!] URL list file not found: {url_file}")
        sys.exit(1)

    # Create output directories
    for folder in FOLDERS:
        Path(folder).mkdir(exist_ok=True)

    # Read non-empty URL lines
    urls = [line.strip() for line in url_file.read_text().splitlines() if line.strip()]
    if not urls:
        print("[!] No valid URLs found in the input file.")
        sys.exit(1)

    # Process each URL in all three modes
    for url in urls:
        for folder_name, opts in FOLDERS.items():
            run_katana(url, Path(folder_name), opts)

if __name__ == '__main__':
    main()