#!/usr/bin/env python3
import argparse
import requests
from rich.console import Console
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()

def print_banner():
    banner = r"""[red]    __  __               __               __  __            __           
[blue]   / / / /__  ____ _____/ /__  __________/ / / /_  ______  / /____  _____[/blue]
[red]  / /_/ / _ \/ __ `/ __  / _ \/ ___/ ___/ /_/ / / / / __ \/ __/ _ \/ ___/[/red]
[blue] / __  /  __/ /_/ / /_/ /  __/ /  (__  ) __  / /_/ / / / / /_/  __/ /    [/blue]
[red]/_/ /_/\___/\__,_/\__,_/\___/_/  /____/_/ /_/\__,_/_/ /_/\__/\___/_/     [/red]
"""
    console.print(f"{banner}\n", markup=True)
    console.print("Check security headers for a list of URLs.\n", style="bold white")

def check_security_headers(url: str):
    # Если URL не содержит схемы, добавляем http://
    if not url.startswith(('http://', 'https://')):
        url = "http://" + url
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        final_url = response.url
        headers = response.headers
        security_headers = {
            "Content-Security-Policy": False,
            "Strict-Transport-Security": False,
            "X-Content-Type-Options": False,
            "Cache-Control": False
        }
        for header in security_headers:
            if header in headers:
                security_headers[header] = True
        return security_headers, final_url, None
    except requests.exceptions.Timeout:
        return None, url, f"Timeout occurred while trying to reach URL {url}."
    except requests.exceptions.ConnectionError:
        return None, url, f"Connection error occurred while trying to reach URL {url}."
    except requests.exceptions.RequestException as e:
        return None, url, f"Error processing URL {url}: {e}"

def process_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    headers, final_url, error_message = check_security_headers(url)
    lines = [f"[blue]Checking URL:[/blue] {url}"]
    if final_url != url:
        lines.append(f"  [yellow]Redirected to:[/yellow] {final_url}")
    if error_message:
        # Добавляем сообщение об ошибке в финальный вывод
        lines.append(f"  [red]{error_message}[/red]")
        lines.append("")
        return "\n".join(lines)
    if headers is not None:
        for header, present in headers.items():
            emoji = "[bold bright_green]+[/bold bright_green]" if present else "[bold bright_red]![/bold bright_red]"
            lines.append(f"  {header}: {emoji}")
        lines.append("")
    return "\n".join(lines)

def process_urls(urls, output_file=None):
    results = []
    urls = [url for url in urls if url.strip()]
    total = len(urls)
    # Один общий прогресс-бар для всех URL
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing URLs...", total=total)
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_url = {executor.submit(process_url, url): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = f"[red]Error processing URL {url}: {e}[/red]"
                results.append(result)
                progress.advance(task)
    # Вывод результатов после завершения работы прогресс-бара
    console.print("\n[bold underline]Results:[/bold underline]\n")
    for res in results:
        if res:
            console.print(res)
    if output_file:
        try:
            with open(output_file, 'w') as f:
                for res in results:
                    f.write(res + "\n")
            console.print(f"[green]Results written to {output_file}[/green]")
        except Exception as e:
            console.print(f"[red]Error writing to file {output_file}: {e}[/red]")
    return results

def main(input_file=None, url_list=None, output_file=None):
    urls = []
    if url_list:
        urls = url_list
    elif input_file:
        try:
            with open(input_file, 'r') as f:
                urls = f.readlines()
        except FileNotFoundError:
            console.print(f"[red]File {input_file} not found.[/red]")
            return
    if urls:
        process_urls(urls, output_file)
    else:
        console.print("[yellow]No URLs to process.[/yellow]")

if __name__ == "__main__":
    print_banner()  # Вывод баннера при запуске
    parser = argparse.ArgumentParser(
        usage="HeadersHunter.py [-h] (-i FILE | -u URL [URL ...]) [-o OUTPUT]"
    )
    parser.add_argument('-i', '--input', help='File with URLs.')
    parser.add_argument('-o', '--output', help='File to save results. If not specified, outputs to console.')
    parser.add_argument('-u', '--urls', nargs='+', help='One or more URLs to check for headers.')
    args = parser.parse_args()
    if not args.input and not args.urls:
        parser.print_help()
    else:
        main(input_file=args.input, url_list=args.urls, output_file=args.output)
