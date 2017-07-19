#!/usr/bin/python
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# Operation Red by EdOverflow
#
# TODO:
# - Scan params
# - Allow user to specify payload(s)
# - Add params (/?continue=payload)
# ----------------------------------------------------------------------

import requests
import argparse
import colorama
import re
try:
    from urllib import parse as urlparse
except ImportError:
    import urlparse


# Variables
redirect = open('payloads.txt').read().splitlines()

parser = argparse.ArgumentParser(
    description="Open redirect vulnerability scanner.")
parser.add_argument("-u", "--url", dest="url",
                    help="Scan individual URL for open \
                    redirect vulnerabilities")
parser.add_argument("-t", "--txt", dest="txt",
                    help="Scan text file for open \
                    redirect vulnerabilities")
args = parser.parse_args()


class symbols:
    """
    Standard symbols list.
    """

    error = colorama.Fore.RED + '[!] ' + colorama.Fore.RESET
    success = colorama.Fore.GREEN + '[$] ' + colorama.Fore.RESET
    negative = colorama.Fore.YELLOW + '[-] ' + colorama.Fore.RESET


def traverse(o, tree_types=(list, tuple)):
    '''
    Iterates over all list values.
    '''
    if isinstance(o, tree_types):
        for value in o:
            for subvalue in traverse(value, tree_types):
                yield subvalue
    else:
        yield o


def url_clean(self, url):
    """
    Cleans up URLs.
    """

    url = url.split('?')[0]
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')
    return(url)


def url_handler(url):
    """
    Parses URLs.
    """

    try:
        # Scheme: http://
        default_protocol = 'http'
        if ('://' not in url):
            url = default_protocol + '://' + url_clean(url)
        scheme = urlparse.urlparse(url).scheme

        # Domain: example.com
        domain = urlparse.urlparse(url).netloc

        # Site: http://example.com
        site = scheme + '://' + domain
        if site.endswith('/') == False:
            site += '/'

    except IndexError:
        pass

    return site


def scan(domains):
    '''
    Scans target, iterates over payloads list and
    checks whether the URL redirects to example.com.
    '''
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
        AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept': 'text/html,\
        application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.8',
        'Accept-Encoding': 'gzip'
    }
    for n in traverse(redirect):
        strip = repr(domains).replace("'", "")
        target = url_handler(strip) + repr(n).replace("'", "")
        print("Scanning: " + target)
        resp = requests.get(target,
                            headers=headers,
                            timeout=5,
                            stream=True,
                            verify=True)
        status = resp.status_code
        no_results = 'No open redirect found.'
        if resp.history:
            if resp.url.startswith("http://example.com"):
                print("=" * 69)
                for r in resp.history:
                    print(symbols.success + "URL is vulnerable to open redirects!")
                    print(str(resp.status_code) + ": " + r.url)
                    print("Final destination:")
                    print(str(resp.status_code) + ": " + resp.url)
                    print("=" * 69)
            else:
                pass
        else:
            print(symbols.negative + no_results)

if args.url:
    '''
    Scans a single URL.
    '''
    try:
        domains = args.url
        scan(domains)
    except requests.exceptions.ConnectionError:
        print(symbols.error + args.url + ": Connection refused!")
        pass
    except requests.exceptions.Timeout:
        print(symbols.error + args.url + ": Connection timed out!")
        pass
    except requests.exceptions.InvalidURL as e:
        print(symbols.error + args.url + ": Invalid URL!")
        pass
    except requests.exceptions.TooManyRedirects:
        print(symbols.error + "Bad URL!")
elif args.txt:
    '''
    Scans a list of targets from a
    text file.
    '''
    domains = open(args.txt).read().splitlines()
    for i in traverse(domains):
        try:
            scan(i)
        except requests.exceptions.ConnectionError as e:
            continue
        except requests.exceptions.Timeout as e:
            continue
        except requests.exceptions.InvalidURL as e:
            continue
        except requests.exceptions.TooManyRedirects:
            print(symbols.error + "Bad URL!")
else:
    parser.print_help()
