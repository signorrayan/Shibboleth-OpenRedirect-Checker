import aiohttp
import asyncio
import sys
import argparse
from typing import List, Tuple
from aiohttp import ClientTimeout
from urllib.parse import urljoin


async def check_domain(session: aiohttp.ClientSession, domain: str) -> Tuple[str, bool, str, bool]:
    """
    Check a domain for Shibboleth logout path and redirection vulnerability.
    Returns tuple of (domain, path_exists, message, is_vulnerable)
    """
    base_url = urljoin(domain, '/Shibboleth.sso/Logout')

    try:
        async with session.get(base_url, timeout=ClientTimeout(total=30)) as response:
            text = await response.text()

            if ('Logout completed successfully' in text or 'Local Logout' in text):
                redirect_url = f"{base_url}?return=https://github.com"
                async with session.get(redirect_url, timeout=ClientTimeout(total=30),
                                       allow_redirects=False) as redirect_response:
                    redirect_text = await redirect_response.text()
                    location = redirect_response.headers.get('location', '')

                    is_vulnerable = ('github.com' in redirect_text.lower() or
                                     'github.com' in location.lower())

                    return domain, True, "Have Shibboleth SSO", is_vulnerable

            return domain, False, "", False

    except asyncio.TimeoutError:
        return domain, False, "Timeout", False
    except Exception as e:
        return domain, False, f"Error: {str(e)}", False


async def check_domains_live(domains: List[str], success_only: bool = False, max_concurrent: int = 100) -> List[
    Tuple[str, bool, str, bool]]:
    ssl_context = False
    conn = aiohttp.TCPConnector(ssl=ssl_context, limit=max_concurrent)
    results = []

    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [check_domain(session, domain) for domain in domains]

        if success_only:
            print("\n=== Potential Vulnerable Domains ===")
        else:
            print("\n=== Live Results ===")
        print("-" * 80)

        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            print_result(result, success_only)

    return results


def print_result(result: Tuple[str, bool, str, bool], success_only: bool = False):
    domain, path_exists, message, is_vulnerable = result
    if path_exists:
        vuln_status = "🔴" if is_vulnerable else "🟢"
        if is_vulnerable:
            print(f"{vuln_status} Vulnerable: {domain}/Shibboleth.sso/Logout?return=https://github.com")
        if not success_only:
            print(f"DEBUG [{domain}]: {message}")
    elif not success_only:
        print(f"✗ {domain}")

def print_summary(results: List[Tuple[str, bool, str, bool]]):
    successful = [(domain, is_vuln) for domain, success, _, is_vuln in results if success]
    vulnerable = [domain for domain, is_vuln in successful if is_vuln]

    total_domains = len(results)
    total_successful = len(successful)
    total_vulnerable = len(vulnerable)

    print(f"\n=== Summary ===")
    print(f"Total domains checked: {total_domains}")
    print(f"Number of assets that have Shibboleth SSO: {total_successful}")
    print(f"Vulnerable to open redirect: {total_vulnerable}")


async def ensure_https(domain: str) -> str:
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
    args = parser.parse_args()

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
    results = await check_domains_live(domains, args.success_only, args.concurrent)
    print_summary(results)


if __name__ == "__main__":
    asyncio.run(main())
