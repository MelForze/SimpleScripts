#!/usr/bin/env python3

import argparse
import requests

def check_security_headers(url):
    """Checks the presence of security headers in the response for the given URL."""
    try:
        # Send a GET request with a specified timeout, following redirects
        response = requests.get(url, allow_redirects=True, timeout=10)
        
        # Final URL after redirects
        final_url = response.url
        headers = response.headers

        security_headers = {
            "Content-Security-Policy": False,
            "Strict-Transport-Security": False,
            "X-Content-Type-Options": False,
            "Cache-Control": False
        }

        for header in security_headers.keys():
            if header in headers:
                security_headers[header] = True

        return security_headers, final_url

    except requests.exceptions.Timeout:
        print(f"Timeout occurred while trying to reach URL {url}.")
        return None, url
    
    except requests.exceptions.ConnectionError:
        print(f"Connection error occurred while trying to reach URL {url}.")
        return None, url

    except requests.exceptions.RequestException as e:
        print(f"Error processing URL {url}: {e}")
        return None, url

def process_urls(urls, output_file=None):
    """Processes a list of URLs and prints the results of security header checks."""
    results = []
    for url in urls:
        url = url.strip()
        if not url:
            continue
        
        security_headers, final_url = check_security_headers(url)
        
        result_lines = [f"Checking URL: {url}"]
        if final_url != url:
            result_lines.append(f"  Redirected to: {final_url}")
        
        if security_headers is not None:
            for header, present in security_headers.items():
                emoji = "✅" if present else "❌"
                result_lines.append(f"  {header}: {emoji}")
            result_lines.append("")  # Empty line for separating outputs

        result = "\n".join(result_lines)
        results.append(result)

        if output_file is None:
            print(result)

    if output_file is not None:
        with open(output_file, 'w') as f_out:
            for result in results:
                f_out.write(result + '\n')

def main(input_file=None, url_list=None, output_file=None):
    """Main function for processing input and executing checks."""
    urls = []
    if url_list:
        urls = url_list
    elif input_file:
        try:
            with open(input_file, 'r') as f:
                urls = f.readlines()
        except FileNotFoundError:
            print(f"File {input_file} not found.")
            return

    if urls:
        process_urls(urls, output_file)
    else:
        print("No URLs to process.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check security headers for a list of URLs.")
    parser.add_argument('-i', '--input', help='File with URLs.')
    parser.add_argument('-o', '--output', help='File to save results. If not specified, outputs to console.')
    parser.add_argument('-u', '--urls', nargs='+', help='One or more URLs to check for headers.')

    args = parser.parse_args()

    if not args.input and not args.urls:
        parser.print_help()
    else:
        main(input_file=args.input, url_list=args.urls, output_file=args.output)