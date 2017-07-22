#!/usr/bin/python
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------
# Operation Red by EdOverflow
# Twitter: https://twitter.com/EdOverflow
# GitHub:  https://github.com/EdOverflow
#
# TODO:
# - Scan params.
# + Allow user to specify payload(s).
# + Add params (/?continue=payload).
# - Replace IP payloads with correct IP.
# - Add random user agents.
# - Fix the detection mechanism.
# - Print logo.
# - Replace www.victim.com with the scanned domain
# - Detect redirection to non-http(s) protocols, like data: and javascript: (tip do this by simply matching if the input is the same as the Location header output)
#----------------------------------------------------------------------

# Modules
import requests
import argparse
import colorama
import re
import os
# Python 2 & 3 require different
# urlparse modules
try:
    from urllib import parse as urlparse
except ImportError as e:
    import urlparse


def version():
    '''
    Return version of Operatio Red.
    '''
    version = 'v.1.0.0'
    return(version)


def logo():
    '''
    Operation Red logo.
    '''
    logo = '''
    Operation Red ''' + version() + '''\n
    Author: EdOverflow
    '''
    return(logo)


# Argument Parser
parser = argparse.ArgumentParser(
    description='A simple Python open redirect vulnerability scanner.'
)
parser.add_argument("-u", "--url", dest="url",
                    help="Scan individual URL for open \
                    redirect vulnerabilities")
parser.add_argument("-t", "--txt", dest="txt",
                    help="Scan text file for open \
                    redirect vulnerabilities")
parser.add_argument("-p", "--payloads", dest="payloads",
                    help="Specify payload list to use \
                    during scan.", default="payloads.txt")
parser.add_argument("-m", "--mypayload", dest="mypayload",
                    help="Specifiy your own payload.")
parser.add_argument("-c", "--common", dest="params",
                    help="Brute force commonly vulnerable \
                    parameters and then test for open redirect\
                    issues.")
args = parser.parse_args()


# User supplied payload.
if args.mypayload:
    redirect = args.mypayload
else:
    # Payload list.
    with open(args.payloads, 'r') as f:
        redirect = f.read().splitlines()


class symbols:
    '''
    Standard symbols list.
    [!] represents an error.
    [$] is for good news!
    [-] is for bad news.
    '''
    error = colorama.Fore.RED + '[!] ' + colorama.Fore.RESET
    success = colorama.Fore.GREEN + '[$] ' + colorama.Fore.RESET
    negative = colorama.Fore.YELLOW + '[-] ' + colorama.Fore.RESET
    info = colorama.Fore.BLUE + '[i] ' + colorama.Fore.RESET


def traverse(o, tree_types=(list, tuple)):
    '''
    Iterates over all list values.
    This function is used whenever a list is being used.
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
    Makes sure that the URL is in one of the following formats:
    (Without parameter) http://example.com/
    (With parameter)    http://example.com/?url=
    """
    try:
        # Scheme: http://
        default_protocol = 'http'
        if ('://' not in url):
            url = default_protocol + '://' + url_clean(url)
        scheme = urlparse.urlparse(url).scheme

        # Domain: example.com
        domain = urlparse.urlparse(url).netloc

        # Site: http://example.com/
        site = scheme + '://' + domain
        if site.endswith('/') == False:
            site += '/'

        if args.params:
            '''
            Tests commonly vulnerable parameters.
            The paramater list can be specified using -c/--common.
            common.txt is Operation Red's ready-made list.
            $ python openred.py -u http://example.com -c common.txt
            '''
            with open(args.params, 'r') as f:
                common_params = f.read().splitlines()

            for p in traverse(common_params):
                # Param: /?url=
                param = site + '?' + repr(p).replace("'", "") + '='
                return(param)
        else:
            return(site)

    except IndexError as e:
        pass


def scan(domains):
    '''
    Scans target, iterates over payloads list and
    checks whether the URL redirects to the payload's
    location.
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
        # Send request to target.
        resp = requests.get(target,
                            headers=headers,
                            timeout=5,
                            stream=True,
                            verify=True)
        status = resp.status_code
        no_results = 'No open redirect found.'
        if resp.history:
            if args.mypayload:
                loc = args.maypayload
            # Open redirect found.
            elif args.payloads:
                loc = 'http://example.com'
            if resp.url.startswith(loc):
                times = 69 # Hehehe
                print("=" * times)
                for r in resp.history:
                    print(symbols.success + "URL is vulnerable to \
                        open redirects!")
                    print(str(resp.status_code) + ": " + r.url)
                    print("Final destination:")
                    print(str(resp.status_code) + ": " + resp.url)
                    print("=" * times)
            else:
                pass
        # No open redirect found.
        else:
            print(symbols.negative + no_results)


def main():
    '''
    Main function.
    - Windows colorama support.
    - Print Operation Red logo.
    '''
    # This allows colorama to run
    # on Windows.
    colorama.init(autoreset=True)
    logo()

    if args.url:
        '''
        Scans a single URL.
        $ python openred.py -u http://example.com/
        '''
        try:
            domains = args.url
            scan(domains)
        except requests.exceptions.ConnectionError as e:
            print(symbols.error + args.url + ": Connection refused!")
            pass
        except requests.exceptions.Timeout as e:
            print(symbols.error + args.url + ": Connection timed out!")
            pass
        except requests.exceptions.InvalidURL as e:
            print(symbols.error + args.url + ": Invalid URL!")
            pass
        except requests.exceptions.TooManyRedirects as e:
            print(symbols.error + "Bad URL! Too many\
                    redirects.")
    elif args.txt:
        '''
        Scans a list of targets from a
        text file.
        $ python -t targets.txt
        '''
        with open(args.txt, 'r') as f:
            domains = f.read().splitlines()
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
                print(symbols.error + "Bad URL! Too many\
                        redirects.")
    else:
        parser.print_help()


if (__name__ == '__main__'):
    try:
        main()
    except KeyboardInterrupt as e:
        print('\n' + symbols.info + 'KeyboardInterrupt detected.')
        os._exit(1)
        
