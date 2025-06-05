import argparse
import logging
from web_exploitation.ssti import SSTIScanner

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def main():
    parser = argparse.ArgumentParser(description='SSTI Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--cookies', help='Cookies in format key1=value1;key2=value2')
    parser.add_argument('--headers', help='Headers in format key1=value1;key2=value2')
    
    args = parser.parse_args()
    
    # Parse cookies and headers if provided
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    
    headers = {}
    if args.headers:
        for header in args.headers.split(';'):
            if '=' in header:
                key, value = header.split('=', 1)
                headers[key.strip()] = value.strip()
    
    # Initialize and run the scanner
    scanner = SSTIScanner(args.url, cookies=cookies, headers=headers)
    results = scanner.scan_url()
    
    # Print the report
    print(scanner.generate_report(results))

if __name__ == '__main__':
    setup_logging()
    main()
