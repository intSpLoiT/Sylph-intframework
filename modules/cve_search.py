#!/usr/bin/env python3
import requests
import json
import sys
import time
import argparse
from bs4 import BeautifulSoup
from multiprocessing import Pool, cpu_count

cves = []

def search_cve(link, startIndex="0"):
    link = link + "&startIndex=" + startIndex

    global cves
    response = requests.get(link)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        matching_records_count = int(soup.find('strong', {'data-testid': 'vuln-matching-records-count'}).text)
        displaying_count_through = int(soup.find('strong', {'data-testid': 'vuln-displaying-count-through'}).text)

        for result in soup.find_all(lambda tag: tag.name == 'a' and tag.get('data-testid', '').startswith('vuln-detail-link-')):
            cve = result.text.strip()
            if cve not in cves:
                cves.append(cve)
    else:
        return None

    return [matching_records_count, displaying_count_through]

def fetch_cve_pages(args):
    url, index = args
    search_cve(url, str(index))

def search_github_cve(cve_search):
    api_url = f"https://api.github.com/search/repositories?q={cve_search}"
    headers = {"Accept": "application/vnd.github.v3+json"}

    cve_response = requests.get(api_url, headers=headers)
    if cve_response.status_code == 200:
        data = json.loads(cve_response.text)
        for item in data.get("items", []):
            html_url = item.get("html_url")
            if html_url:
                print(html_url)

def process_cves(url, matching_records_count, displaying_count_through):
    indices = range(displaying_count_through, matching_records_count + 1, displaying_count_through)
    with Pool(cpu_count()) as pool:
        pool.map(fetch_cve_pages, [(url, index) for index in indices])

def main():
    global kernel_version, cves

    parser = argparse.ArgumentParser(description="Github payload searcher by shinningstar")
    parser.add_argument('-c', '--cve', type=str, help='CVE string (Ex: CVE-2023-27163)')
    parser.add_argument('-k', '--kernel', type=str, help='Linux kernel string (Ex: 5.15.70)')
    parser.add_argument('-p', '--product', type=str, help='Product to be scanned (Ex: Joomla)')
    parser.add_argument('-pv', '--productversion', type=str, help='Version of the product (Ex: 4.2.6)')

    args = parser.parse_args()

    if not args.cve and not args.kernel and not args.product:
        parser.print_help()
        sys.exit(1)

    if args.product and not args.productversion:
        print("You must enter the product version")
        sys.exit(1)

    kernel_version = args.kernel or ""
    cve_search_str = args.cve or ""

    if cve_search_str == "":
        if kernel_version:
            url = f"https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&cpe_vendor=cpe%3A%2F%3Alinux&cpe_version=cpe%3A%2F%3Alinux%3Alinux_kernel%3A{kernel_version}&query=escalate&cpe_product=cpe%3A%2F%3Alinux%3Alinux_kernel&results_type=overview&form_type=Advanced&search_type=all"
        elif args.product:
            product = args.product.lower()
            product_version = args.productversion.lower().replace(" ", "")
            url = f"https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&&cpe_product=cpe:/::{product}:{product_version}"

        get_first_cve = search_cve(url)
        if args.product and (get_first_cve == None or get_first_cve == [0, 0]):
            time.sleep(5)
            url = f"https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&&cpe_product=cpe:/:{product}::{product_version}"
            get_first_cve = search_cve(url)

        if get_first_cve == None or get_first_cve == [0, 0]:
            print("No CVEs found!")
            exit()

        matching_records_count = get_first_cve[0]
        displaying_count_through = get_first_cve[1]

        process_cves(url, matching_records_count, displaying_count_through)

        if cves:
            print("CVEs found:")
            for cve in cves:
                print(cve)
                search_github_cve(cve.replace(" ", ""))
        else:
            print("No CVEs found for the specified kernel version.")
    else:
        print("Public GitHub links related to CVE", cve_search_str)
        search_github_cve(cve_search_str.replace(" ", ""))

if __name__ == "__main__":
    main()