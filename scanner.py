import json
import ssl
import socket
from datetime import datetime

import requests

sites = [
    'https://github.com',
    'https://google.com',
    'https://northeastern.edu',
    'https://reddit.com'
]

def check_ssl(url):
    """Checks SSL certificate validity"""
    ssl_data = {}

    # extracts hostname from the url (https://github.com -> github.com)
    hostname = url.replace('https://', '').replace('http://', '').split('/')[0]

    try:
        # creates SSL context
        context = ssl.create_default_context()

        # connects to website with hostname and port 443 (https)
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            # wraps the socket in SSL encryption and tells SSl what domain we're expecting
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                # gets certificate from the server. cert is a dictionary with all certificate info
                cert = secure_sock.getpeercert()

                # check expiration and calculate days til expiration
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.now()).days

                # stores all important data in a dictionary
                ssl_data = {
                    'issued_to': cert['subject'][0][0][1], # gets the nested commonName
                    'expires': expiry_date.strftime('%Y-%m-%d'),
                    'days_until_expiry': days_until_expiry,
                    'expiring_soon': days_until_expiry < 30
                }


                print(f"\nSSL Certificate Info:")
                print(f"  -> Issued to: {cert['subject'][0][0][1]}")
                print(f"  -> Expires: {expiry_date.strftime('%Y-%m-%d')}")
                print(f"  -> Days until expiry: {days_until_expiry}")
                if days_until_expiry < 30:
                    print(f"  ⚠️  Certificate expiring soon!")

    except Exception as e:
        ssl_data = {'error': str(e)}
        print(f"\n SSL Check Failed: {e}")

    return ssl_data

def check_url(url):

    results = {
        'url': url,
        'headers_found': [],
        'headers_missing': [],
        'security_score': 0,
        'ssl_info': {}
    }

    try:
        req = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {url}: {e}")
        results['error'] = str(e)
        return results

    security_headers = {
        'X-Frame-Options': 'Prevents clickjacking attacks',
        'X-Content-Type-Options': 'Prevents MIME-sniffing',
        'Strict-Transport-Security': 'Enforces HTTPS connections',
        'Content-Security-Policy': 'Controls what resources can load',
        'Referrer-Policy': 'Controls how much referrer information is shared',
        'Permissions-Policy': 'Controls browser features (camera, microphone, etc.)',
        'X-XSS-Protection': 'Legacy XSS filter (deprecated but still checked)',
        'Cross-Origin-Opener-Policy': 'Isolates browsing context from other windows',
        'Cross-Origin-Embedder-Policy': 'Prevents loading unauthorized cross-origin resources',
        'Cross-Origin-Resource-Policy': 'Protects resources from being loaded by other origins'
    }

    counter = 0
    for header, description in security_headers.items():
        if header in req.headers:
            print(f"{header} is present in {url}")
            print(f" -> {description}")
            results['headers_found'].append({
                'name': header,
                'value': req.headers[header],
                'description': description
            })
            counter += 1
        else:
            print(f"{header} is missing in {url}")
            print(f" -> {description}")
            results['headers_missing'].append({
                'name': header,
                'description': description
            })

    security_score = 100 * counter / len(security_headers)
    results['security_score'] = security_score
    print(f'The security score for this website is {counter}/{len(security_headers)} ({security_score}%)')

    results['ssl_info'] = check_ssl(url)
    return results

def check_multiple_url(urls):
    """Scan multiple websites"""
    all_results = []

    for i, url in enumerate(urls, 1):
        print(f"\n{'='*60}") # prints # 60 times as divider
        print(f"Scanning {i}/{len(urls)}: {url}") # keeps track of progress (1/4, 2/4, etc.)
        print(f"{'='*60}") # another divider

        result = check_url(url)
        all_results.append(result)
        print()  # extra line between scans

    save_results_to_json(all_results)
    return all_results


def save_results_to_json(all_results, filename='security_scan_results.json'):
    """Save results to a JSON file"""
    scan_data = {
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_sites': len(all_results),
        'results': all_results
    }

    with open(filename, 'w') as f:
        json.dump(scan_data, f, indent=4)

    print(f"\nResults saved to {filename}")


check_multiple_url(sites)




