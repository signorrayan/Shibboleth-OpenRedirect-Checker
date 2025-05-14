import argparse
import asyncio
import json
import re
import sys
import time
from datetime import datetime
from typing import List, Tuple

import aiohttp
from aiohttp import ClientTimeout


async def check_domain(session: aiohttp.ClientSession, domain: str, debug: bool = False,
                       semaphore: asyncio.Semaphore = None) -> Tuple[str, bool, str, bool]:
    """
    Check a domain for Shibboleth logout path and redirection vulnerability.
    Returns tuple of (domain, path_exists, message, is_vulnerable)
    """

    async with semaphore if semaphore else asyncio.Lock():

        domain = domain.rstrip('/')
        base_url = f"{domain}/Shibboleth.sso/Logout"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }

        try:

            async with session.get(base_url, timeout=ClientTimeout(total=30),
                                   headers=headers, ssl=False) as response:
                text = await response.text()
                status_code = response.status

                shibboleth_indicators = [
                    'logout completed successfully',
                    'local logout',
                    'shibboleth',
                    'saml',
                    'idp logout',
                    'you have successfully logged out',
                    'logout successful',
                    'session expired'
                ]

                has_shibboleth = any(indicator in text.lower() for indicator in shibboleth_indicators)

                if status_code == 200 or has_shibboleth:

                    redirect_url = f"{base_url}?return=https://github.com/test"

                    async with session.get(redirect_url, timeout=ClientTimeout(total=30),
                                           headers=headers, ssl=False,
                                           allow_redirects=True) as redirect_response:
                        final_url = str(redirect_response.url)
                        redirect_text = await redirect_response.text()

                        async with session.get(redirect_url, timeout=ClientTimeout(total=30),
                                               headers=headers, ssl=False,
                                               allow_redirects=False) as no_redirect_response:
                            location_header = no_redirect_response.headers.get('location', '')
                            refresh_header = no_redirect_response.headers.get('refresh', '')
                            no_redirect_text = await no_redirect_response.text()

                        from urllib.parse import urlparse

                        final_url_parsed = urlparse(final_url)
                        final_url_is_github = 'github.com' in final_url_parsed.netloc.lower()

                        location_is_github = False
                        if location_header:

                            if location_header.startswith('http'):
                                location_parsed = urlparse(location_header)
                                location_is_github = 'github.com' in location_parsed.netloc.lower()
                            else:

                                location_is_github = location_header.lower().startswith('//github.com')

                        meta_refresh_to_github = False
                        meta_refresh_match = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*>', no_redirect_text,
                                                       re.IGNORECASE)
                        if meta_refresh_match:
                            content = meta_refresh_match.group(1)

                            url_match = re.search(r'url\s*=\s*([^\s;]+)', content, re.IGNORECASE)
                            if url_match:
                                refresh_url = url_match.group(1).strip('"\'')
                                if refresh_url.startswith('http'):
                                    refresh_parsed = urlparse(refresh_url)
                                    meta_refresh_to_github = 'github.com' in refresh_parsed.netloc.lower()
                                else:
                                    meta_refresh_to_github = refresh_url.lower().startswith('//github.com')

                        js_redirect_to_github = False
                        js_redirect_pattern = r'(window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']'
                        js_matches = re.finditer(js_redirect_pattern, no_redirect_text, re.IGNORECASE)
                        for match in js_matches:
                            redirect_value = match.group(2)
                            if redirect_value.startswith('http'):
                                js_parsed = urlparse(redirect_value)
                                if 'github.com' in js_parsed.netloc.lower():
                                    js_redirect_to_github = True
                                    break
                            elif redirect_value.lower().startswith('//github.com'):
                                js_redirect_to_github = True
                                break

                        refresh_header_to_github = False
                        if refresh_header:

                            url_match = re.search(r'url\s*=\s*([^\s;]+)', refresh_header, re.IGNORECASE)
                            if url_match:
                                refresh_url = url_match.group(1).strip('"\'')
                                if refresh_url.startswith('http'):
                                    refresh_parsed = urlparse(refresh_url)
                                    refresh_header_to_github = 'github.com' in refresh_parsed.netloc.lower()
                                else:
                                    refresh_header_to_github = refresh_url.lower().startswith('//github.com')

                        vulnerability_checks = [
                            final_url_is_github,
                            location_is_github,
                            meta_refresh_to_github,
                            js_redirect_to_github,
                            refresh_header_to_github
                        ]

                        is_vulnerable = any(vulnerability_checks)

                        if debug:
                            print(f"\n==========================================")
                            print(f"URL: {base_url}")
                            print(f"Status: {status_code}")
                            print(f"Final URL: {final_url}")
                            print(f"Final URL is GitHub: {final_url_is_github}")
                            print(f"Location Header: {location_header}")
                            print(f"Location is GitHub: {location_is_github}")
                            print(f"Refresh Header: {refresh_header}")
                            print(f"Refresh Header to GitHub: {refresh_header_to_github}")
                            print(f"Meta Refresh to GitHub: {meta_refresh_to_github}")
                            print(f"JS Redirect to GitHub: {js_redirect_to_github}")
                            print(f"Has Shibboleth: {has_shibboleth}")
                            print(f"Is Vulnerable: {is_vulnerable}")
                            print(f"==========================================\n")

                        return domain, True, "Has Shibboleth SSO", is_vulnerable

                return domain, False, "No Shibboleth endpoint", False

        except asyncio.TimeoutError:
            return domain, False, "Timeout", False
        except aiohttp.ClientConnectorError as e:
            return domain, False, f"Connection error: {str(e)}", False
        except Exception as e:
            return domain, False, f"Error: {str(e)}", False


async def check_domains_batch(domains: List[str], session: aiohttp.ClientSession,
                              semaphore: asyncio.Semaphore, success_only: bool = False,
                              debug: bool = False, progress_callback=None) -> List[Tuple[str, bool, str, bool]]:
    """Process a batch of domains"""
    tasks = []
    for domain in domains:
        task = check_domain(session, domain, debug, semaphore)
        tasks.append(task)

    results = []
    for i, coro in enumerate(asyncio.as_completed(tasks)):
        try:
            result = await coro
            results.append(result)
            print_result(result, success_only)
            if progress_callback:
                progress_callback(i + 1, len(tasks))
        except Exception as e:
            print(f"Error processing domain: {e}")

    return results


async def check_domains_live(domains: List[str], success_only: bool = False,
                             max_concurrent: int = 100, debug: bool = False,
                             batch_size: int = 500) -> List[Tuple[str, bool, str, bool]]:
    """Check multiple domains concurrently with batching for large lists"""

    semaphore = asyncio.Semaphore(max_concurrent)

    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=0,
        limit_per_host=30,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
        force_close=True
    )

    results = []

    timeout = ClientTimeout(total=45, connect=15, sock_connect=15, sock_read=15)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        if success_only:
            print("\n=== Potential Vulnerable Domains ===")
        else:
            print("\n=== Live Results ===")
        print("-" * 80)

        total_domains = len(domains)
        processed = 0

        for batch_start in range(0, total_domains, batch_size):
            batch_end = min(batch_start + batch_size, total_domains)
            batch = domains[batch_start:batch_end]

            print(f"\nProcessing batch {batch_start + 1}-{batch_end} of {total_domains}")

            def progress_callback(current, total):
                nonlocal processed
                processed += 1
                if processed % 50 == 0:
                    print(f"Progress: {processed}/{total_domains} ({processed / total_domains * 100:.1f}%)")

            batch_results = await check_domains_batch(
                batch, session, semaphore, success_only, debug, progress_callback
            )
            results.extend(batch_results)

            if batch_end < total_domains:
                await asyncio.sleep(1)

    return results


def print_result(result: Tuple[str, bool, str, bool], success_only: bool = False):
    """Print individual result"""
    domain, path_exists, message, is_vulnerable = result

    if path_exists:
        vuln_status = "🔴 VULNERABLE" if is_vulnerable else "🟢 SECURE"
        if is_vulnerable:
            print(f"{vuln_status}: {domain}/Shibboleth.sso/Logout?return=https://github.com")
        elif not success_only:
            print(f"{vuln_status}: {domain} - {message}")
    elif not success_only:
        print(f"✗ {domain} - {message}")


def print_summary(results: List[Tuple[str, bool, str, bool]]) -> List[str]:
    """Print summary and return vulnerable domains"""
    successful = [(domain, is_vuln) for domain, success, _, is_vuln in results if success]
    vulnerable = [domain for domain, is_vuln in successful if is_vuln]
    failed = [domain for domain, success, _, _ in results if not success]

    total_domains = len(results)
    total_successful = len(successful)
    total_vulnerable = len(vulnerable)
    total_failed = len(failed)

    print(f"\n=== Summary ===")
    print(f"Total domains checked: {total_domains}")
    print(f"Number of assets that have Shibboleth SSO: {total_successful}")
    print(f"Vulnerable to open redirect: {total_vulnerable}")
    print(f"Failed/Unavailable: {total_failed}")

    return vulnerable


def save_vulnerable_urls(vulnerable_domains: List[str], output_file: str):
    """Save vulnerable URLs to a file"""
    with open(output_file, 'w') as f:
        for domain in vulnerable_domains:
            vulnerable_url = f"{domain}/Shibboleth.sso/Logout?return=https://github.com"
            f.write(f"{vulnerable_url}\n")
    print(f"\nVulnerable URLs saved to: {output_file}")


def save_detailed_results(results: List[Tuple[str, bool, str, bool]], output_file: str):
    """Save detailed results to JSON file"""
    detailed_results = []
    for domain, has_shibboleth, message, is_vulnerable in results:
        detailed_results.append({
            'domain': domain,
            'has_shibboleth': has_shibboleth,
            'message': message,
            'is_vulnerable': is_vulnerable,
            'timestamp': datetime.now().isoformat()
        })

    with open(output_file, 'w') as f:
        json.dump(detailed_results, f, indent=2)
    print(f"Detailed results saved to: {output_file}")


async def ensure_https(domain: str) -> str:
    """Ensure domain has https:// prefix"""
    if not domain.startswith(('http://', 'https://')):
        return f'https://{domain}'
    return domain


async def main():
    parser = argparse.ArgumentParser(
        description='Check domains for Shibboleth logout path and open redirect vulnerability')
    parser.add_argument('file', nargs='?', help='File containing domains (one per line)')
    parser.add_argument('--success-only', '-s', action='store_true',
                        help='Show only successful domains')
    parser.add_argument('--concurrent', '-c', type=int, default=100,
                        help='Maximum number of concurrent requests (default: 100)')
    parser.add_argument('--batch-size', '-b', type=int, default=500,
                        help='Batch size for processing domains (default: 500)')
    parser.add_argument('--output', '-o', type=str,
                        help='Save all vulnerable URLs to the specified file')
    parser.add_argument('--detailed-output', '-do', type=str,
                        help='Save detailed results to JSON file')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Enable debug output for all domains')
    args = parser.parse_args()

    start_time = time.time()

    if args.file:
        with open(args.file) as f:
            domains = [await ensure_https(line.strip()) for line in f if line.strip()]
    else:
        print("Please provide domains (one per line, press Ctrl+D when done):")
        domains = [await ensure_https(line.strip()) for line in sys.stdin if line.strip()]

    if not domains:
        print("No domains provided!")
        return

    print(f"\nChecking {len(domains)} domains...")
    print(f"Concurrent requests: {args.concurrent}")
    print(f"Batch size: {args.batch_size}")

    results = await check_domains_live(
        domains,
        args.success_only,
        args.concurrent,
        args.debug,
        args.batch_size
    )

    vulnerable_domains = print_summary(results)

    if args.output and vulnerable_domains:
        save_vulnerable_urls(vulnerable_domains, args.output)

    if args.detailed_output:
        save_detailed_results(results, args.detailed_output)

    elapsed_time = time.time() - start_time
    print(f"\nTotal execution time: {elapsed_time:.2f} seconds")
    print(f"Average time per domain: {elapsed_time / len(domains):.2f} seconds")


if __name__ == "__main__":
    asyncio.run(main())
