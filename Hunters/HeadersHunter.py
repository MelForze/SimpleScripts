#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed


def create_argument_parser(*args, **kwargs):
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def build_console():
    try:
        from rich.console import Console
    except ModuleNotFoundError:
        class Console:  # type: ignore[no-redef]
            def print(self, *args, **kwargs):
                print(*args)

    return Console()


def build_progress():
    try:
        from rich.progress import Progress
    except ModuleNotFoundError:
        class Progress:  # type: ignore[no-redef]
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def add_task(self, *args, **kwargs):
                return 0

            def advance(self, *args, **kwargs):
                return None

    return Progress


class LazyRequestsProxy:
    def __getattr__(self, name):
        return getattr(load_requests(), name)


console = build_console()
Progress = build_progress()
requests = LazyRequestsProxy()
MARKUP_TAG_RE = re.compile(r"\[(?:/?[A-Za-z][^\]]*)\]")


def load_requests():
    try:
        import requests as requests_module
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Missing dependency: install 'requests' to use HeadersHunter."
        ) from exc
    return requests_module


def build_parser() -> argparse.ArgumentParser:
    parser = create_argument_parser(
        usage="HeadersHunter.py [-h] (-i FILE | -u URL [URL ...]) [-o OUTPUT] [-debug] [-group]"
    )
    parser.add_argument("-i", "--input", metavar="", help="File with URLs.")
    parser.add_argument(
        "-o",
        "--output",
        metavar="",
        help="File to save results. If not specified, outputs to console.",
    )
    parser.add_argument(
        "-u",
        "--urls",
        metavar="",
        nargs="+",
        help="One or more URLs to check for headers.",
    )
    parser.add_argument("-debug", "--debug", action="store_true", help="Enable debug messages.")
    parser.add_argument("-group", "--group", action="store_true", help="Enable grouped output for URLs.")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def print_banner() -> None:
    banner = r"""[red]    __  __               __               __  __            __           
[blue]   / / / /__  ____ _____/ /__  __________/ / / /_  ______  / /____  _____[/blue]
[red]  / /_/ / _ \/ __ `/ __  / _ \/ ___/ ___/ /_/ / / / / __ \/ __/ _ \/ ___/[/red]
[blue] / __  /  __/ /_/ / /_/ /  __/ /  (__  ) __  / /_/ / / / / /_/  __/ /    [/blue]
[red]/_/ /_/\___/\__,_/\__,_/\___/_/  /____/_/ /_/\__,_/_/ /_/\__/\___/_/     [/red]
"""
    console.print(f"{banner}\n", markup=True)
    console.print("Check security headers for a list of URLs.\n", style="bold white")


def check_security_headers(url: str, debug: bool = False, requests_module=None):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        requests_lib = load_requests() if requests_module is None else requests_module
    except RuntimeError as exc:
        err_msg = str(exc) if debug else "Dependency error."
        return None, url, err_msg

    try:
        response = requests_lib.get(url, allow_redirects=True, timeout=5)
        final_url = response.url
        headers = response.headers
        security_headers = {}
        csp = headers.get("Content-Security-Policy", None)
        if csp is None:
            security_headers["Content-Security-Policy"] = {
                "present": False,
                "unsafe-inline": False,
                "unsafe-eval": False,
            }
        else:
            security_headers["Content-Security-Policy"] = {
                "present": True,
                "unsafe-inline": ("unsafe-inline" in csp),
                "unsafe-eval": ("unsafe-eval" in csp),
            }
        for header in ["Strict-Transport-Security", "X-Content-Type-Options"]:
            security_headers[header] = header in headers
        return security_headers, final_url, None
    except requests_lib.exceptions.Timeout:
        err_msg = (
            f"Timeout occurred while trying to reach URL {url}."
            if debug
            else "Timeout error."
        )
        return None, url, err_msg
    except requests_lib.exceptions.ConnectionError:
        err_msg = (
            f"Connection error occurred while trying to reach URL {url}."
            if debug
            else "Connection error."
        )
        return None, url, err_msg
    except requests_lib.exceptions.RequestException as exc:
        err_msg = f"Error processing URL {url}: {exc}" if debug else "Request error."
        return None, url, err_msg


def process_url(url: str, debug: bool = False) -> dict:
    url = url.strip()
    if not url:
        return {}
    headers, final_url, error_message = check_security_headers(url, debug)
    return {
        "url": url,
        "final_url": final_url,
        "error": error_message,
        "headers": headers,
    }


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        import ipaddress

        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def generate_ordered_detailed_output(results, debug: bool = False):
    successful = [res for res in results if not res.get("error") and res.get("headers") is not None]
    errors = [res for res in results if res.get("error")]
    http_ip = []
    http_domain = []
    https_ip = []
    https_domain = []
    for res in successful:
        url_to_parse = res["final_url"] if res["final_url"] else res["url"]
        parsed = urllib.parse.urlparse(url_to_parse)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        is_ip = _is_ip_host(host)
        if scheme == "http":
            if is_ip:
                http_ip.append((host, res))
            else:
                http_domain.append((host.lower(), res))
        elif scheme == "https":
            if is_ip:
                https_ip.append((host, res))
            else:
                https_domain.append((host.lower(), res))
        else:
            http_domain.append((host.lower(), res))
    http_ip.sort(key=lambda x: x[0])
    http_domain.sort(key=lambda x: x[0])
    https_ip.sort(key=lambda x: x[0])
    https_domain.sort(key=lambda x: x[0])
    output_lines = []

    def format_result_line(res):
        lines = []
        lines.append(f"[blue]Checking URL:[/blue] [blue]{res['url']}[/blue]")
        if res["final_url"] != res["url"]:
            lines.append(f" [yellow]Redirected to:[/yellow] [blue]{res['final_url']}[/blue]")
        for header, value in res["headers"].items():
            if header == "Content-Security-Policy":
                csp = value
                emoji = (
                    "[bold bright_green]+[/bold bright_green]"
                    if csp["present"] and not (csp["unsafe-inline"] or csp["unsafe-eval"])
                    else "[bold bright_red]![/bold bright_red]"
                )
                line = f"   {header}: {emoji}"
                if csp["present"]:
                    line += (
                        f" (unsafe-inline: {'yes' if csp['unsafe-inline'] else 'no'}, "
                        f"unsafe-eval: {'yes' if csp['unsafe-eval'] else 'no'})"
                    )
                lines.append(line)
            else:
                emoji = (
                    "[bold bright_green]+[/bold bright_green]"
                    if value
                    else "[bold bright_red]![/bold bright_red]"
                )
                lines.append(f" {header}: {emoji}")
        return "\n".join(lines)

    def add_group(title, group_list):
        if group_list:
            output_lines.append(f"[bold cyan]{title}[/bold cyan]")
            for _, res in group_list:
                output_lines.append(format_result_line(res))
                output_lines.append("")

    add_group("HTTP IP Addresses", http_ip)
    add_group("HTTP Domain Names", http_domain)
    add_group("HTTPS IP Addresses", https_ip)
    add_group("HTTPS Domain Names", https_domain)
    if debug and errors:
        output_lines.append("[bold red]Errors:[/bold red]")
        for res in errors:
            output_lines.append(f"[red]Error for URL [blue]{res['url']}[/blue]: {res['error']}[/red]")
    return "\n".join(output_lines)


def generate_consolidated_output(results, debug: bool = False):
    outputs = []
    successful = [res for res in results if not res.get("error") and res.get("headers") is not None]
    insecure_csp = []
    for res in successful:
        csp = res["headers"].get("Content-Security-Policy")
        if csp and csp["present"] and (csp["unsafe-inline"] or csp["unsafe-eval"]):
            details = []
            if csp["unsafe-inline"]:
                details.append("unsafe-inline")
            if csp["unsafe-eval"]:
                details.append("unsafe-eval")
            insecure_csp.append((res["url"], details))
    if insecure_csp:
        outputs.append("[white]URLs with insecure Content-Security-Policy (contains unsafe directives):[/white]")
        for url, details in insecure_csp:
            outputs.append(f"[red][!][/red] [blue]{url}[/blue] (contains: {', '.join(details)})")
        outputs.append("")
    insecure_csp_urls = {url for url, _ in insecure_csp}
    groups = {}
    for res in successful:
        if res["url"] in insecure_csp_urls:
            continue
        missing = set()
        for header, value in res["headers"].items():
            if header == "Content-Security-Policy":
                if not value["present"]:
                    missing.add("Content-Security-Policy (missing)")
            elif not value:
                missing.add(header)
        groups.setdefault(frozenset(missing), []).append(res["url"])
    sorted_groups = sorted(groups.items(), key=lambda x: len(x[0]), reverse=True)
    for missing, urls in sorted_groups:
        urls_str = ", ".join(f"[blue]{url}[/blue]" for url in urls)
        if missing:
            outputs.append(f"{urls_str} [red]Don't use the following HTTP security headers:[/red]")
            for header in missing:
                outputs.append(f"   [red]{header}[/red]")
        else:
            outputs.append(f"{urls_str} [green]use all checked HTTP security headers.[/green]")
        outputs.append("")
    if debug:
        error_results = [res for res in results if res.get("error")]
        if error_results:
            outputs.append("[bold red]Errors:[/bold red]")
            for res in error_results:
                outputs.append(f"[red]Error for URL [blue]{res['url']}[/blue]: {res['error']}[/red]")
    return "\n".join(outputs)


def strip_markup(text: str) -> str:
    plain = MARKUP_TAG_RE.sub("", text)
    return plain.replace("[!]", "!")


def process_urls(urls, output_file=None, debug: bool = False, group: bool = False) -> int:
    results = []
    urls = [url.strip() for url in urls if url.strip()]
    total = len(urls)
    if total == 0:
        print("Error: no URLs to process.", file=sys.stderr)
        return 1

    with Progress() as progress:
        task = progress.add_task("[cyan]Processing URLs...", total=total)
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_url = {executor.submit(process_url, url, debug): url for url in urls}
            for future in as_completed(future_to_url):
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "url": future_to_url[future],
                        "error": f"Error processing URL: {exc}",
                        "headers": None,
                        "final_url": future_to_url[future],
                    }
                results.append(result)
                progress.advance(task)

    console.print("\n[bold underline]Results:[/bold underline]\n")
    output_str = generate_consolidated_output(results, debug) if group else generate_ordered_detailed_output(results, debug)
    console.print(output_str)
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as handle:
                handle.write(strip_markup(output_str))
        except OSError as exc:
            print(f"Error writing to file {output_file}: {exc}", file=sys.stderr)
            return 1
        console.print(f"[green]Results written to {output_file}[/green]")
    return 0


def run(input_file=None, url_list=None, output_file=None, debug: bool = False, group: bool = False) -> int:
    urls = []
    if url_list:
        urls = url_list
    elif input_file:
        try:
            with open(input_file, "r", encoding="utf-8") as handle:
                urls = handle.readlines()
        except FileNotFoundError:
            print(f"Error: file {input_file} not found.", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"Error reading file {input_file}: {exc}", file=sys.stderr)
            return 1

    if not urls:
        print("Error: no URLs to process.", file=sys.stderr)
        return 1

    try:
        load_requests()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return process_urls(urls, output_file, debug, group)


def main(argv: list[str] | None = None) -> int:
    print_banner()
    args = parse_args(argv)
    if not args.input and not args.urls:
        print("Error: provide -i/--input or -u/--urls.", file=sys.stderr)
        return 1
    if args.input and args.urls:
        print("Error: use either -i/--input or -u/--urls, not both.", file=sys.stderr)
        return 1
    return run(
        input_file=args.input,
        url_list=args.urls,
        output_file=args.output,
        debug=args.debug,
        group=args.group,
    )


if __name__ == "__main__":
    raise SystemExit(main())
