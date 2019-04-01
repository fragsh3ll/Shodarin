#!/usr/bin/env python3

# Written by Richard Young (@fragsh3ll)

import requests
import argparse
import shodan
import re
import csv
import time
from bs4 import BeautifulSoup

requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.DEFAULT_SSL_CIPHER_LIST += 'HIGH:!DH:!aNULL'
except AttributeError:
    # no pyopenssl support used / needed / available
    pass

# Set Shodan API key here
SHODAN_API_KEY = ''
ARIN_SEARCH_URL = 'https://whois.arin.net/ui/query.do'
ARIN_RDAP_URL = 'https://rdap.arin.net/registry/ip/'

nets = []
orgs = []
cidrs = []
ports = []
orgs_cidr = {}
ipv6_orgs_cidr = {}
specific_ports = False


def banner():
    print('''\

 .::::::.   ::   .:      ...    :::::::-.    :::.    :::::::..   ::::::.    :::.
;;;`    `  ,;;   ;;,  .;;;;;;;.  ;;,   `';,  ;;`;;   ;;;;``;;;;  ;;;`;;;;,  `;;;
'[==/[[[[,,[[[,,,[[[ ,[[     \[[,`[[     [[ ,[[ '[[,  [[[,/[[['  [[[  [[[[[. '[[
  \'\'\'    $"$$$"""$$$ $$$,     $$$ $$,    $$c$$$cc$$$c $$$$$$c    $$$  $$$ "Y$c$$
 88b    dP 888   "88o"888,_ _,88P 888_,o8P' 888   888,888b "88bo,888  888    Y88
  "YMmMY"  MMM    YMM  "YMMMMMP"  MMMMP"`   YMM   ""` MMMM   "W" MMM  MMM     YM
  
                                            Author: @fragsh3ll
    ''')

parser = argparse.ArgumentParser(description=banner())

parser.add_argument('company', help='Company to query on ARIN')
parser.add_argument('-o', '--outfile', help='(Recommended) Name of CSV output file for Shodan results (ARIN results are '
                                            'auto-written to "company"_ipv4.txt and "company"_ipv6.txt)')
parser.add_argument('-p', '--ports', help='Only show results for specified ports (ex: 21,80,443)')
parser.add_argument('-w', '--wildcard', action='store_true', help='Perform a wildcard search. This will search using '
                                                                  '"*company name*" instead of just "company name". '
                                                                  'Not recommended for smaller company names')
parser.add_argument('-a', '--arin', action='store_true', help='Skip Shodan lookup and only output the '
                                                              'discovered CIDR notations from ARIN')
parser.add_argument('-n', '--no-prompt', action='store_true', help='Do not prompt to continue when discovering a large '
                                                                   'amount of results (will just continue)')
args = parser.parse_args()



def main():
    if not args.arin:
        if len(SHODAN_API_KEY) == 0:
            print('[!] Shodan API key is missing! You need to fill in your key before doing Shodan queries!')
            exit(1)

        if args.outfile:
            global csv_writer
            csv_file = open(args.outfile, 'w', encoding='utf-8', newline='')
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(['IP Address', 'Port', 'Domains', 'OS', 'Transport', 'ISP', 'Organization', 'Data',
                                 'HTML Title', 'Server', 'WAF'])
        if args.ports:
            global specific_ports
            global ports
            specific_ports = True
            ports = args.ports.split(',')

        query(args.company)
        print_orgs()
        shodan_query(cidrs)
    else:
        query(args.company)
        print_orgs()
        print('\n[*] Done!')

def query(company):
    results = []
    count = 0
    company = '*'+company+'*' if args.wildcard else company

    print('[*] Searching ARIN for {}...\n'.format(company))
    results.append(requests.post(ARIN_SEARCH_URL, data={'advanced': 'true', 'q': company, 'r': 'ORGANIZATION'}))
    results.append(requests.post(ARIN_SEARCH_URL, data={'advanced': 'true', 'q': company, 'r': 'CUSTOMER'}))

    for i in range(2):
        soup = BeautifulSoup(results[i].text,"html.parser")
        if 'could not be found' in soup.text and i == 0:
            print('[-] Company not found for ORGANIZATION search. Try searching with wildcard (-w).')\
                if not args.wildcard else print('[-] Company not found for ORGANIZATION search.')
        elif 'could not be found' in soup.text and i == 1:
            print('[-] Company not found for CUSTOMER search. Try searching with wildcard (-w).') \
                if not args.wildcard else print('[-] Company not found for CUSTOMER search.')
        elif soup.handle:
            orgs.append(''.join((soup.find_all('name')[1].string,' (',soup.find('handle').string,') ')))
            nets.append(soup.ref.string+'/nets')
        else:
            names = soup.find_all('td')
            for name in names:
                orgs.append(re.sub(' +',' ',name.text))
                nets.append(name.a['href']+'/nets')

    if len(orgs) == 0:
        exit(0)
    elif len(orgs) > 75 and not args.no_prompt:
        ask = input('[*] {} organizations were discovered. This could take some time.\n[*] Are you '
                    'sure you want to continue? [Y/n]: '.format(len(orgs))) or "Y"
        if ask.lower() != 'y':
            print('[*] Exiting...')
            exit(0)

    print('\n[*] {} total results discovered for {}\n'.format(len(orgs), args.company))

    for url in nets:
        print('[*] Checking ' + orgs[count] + 'for netblocks...')
        s = requests.get(url)
        soup = BeautifulSoup(s.text, "html.parser")
        blocks = soup.find_all('netref')
        for block in blocks:
            soup = BeautifulSoup(str(block), "html.parser")
            start = soup.find('netref').get('startaddress')
            end = soup.find('netref').get('endaddress')
            print('\t[+] range: ' + start + ' - ' + end)
            block_json = requests.get(ARIN_RDAP_URL+start).json()
            try:
                for ip in block_json['cidr0_cidrs']:
                    print('\t\t[+] CIDR: {}/{}'.format(ip['v4prefix'],ip['length']))
                    ip_cidr = ''.join((ip['v4prefix'],'/',str(ip['length'])))
                    cidrs.append(ip_cidr)
                    orgs_cidr.setdefault(orgs[count], []).append(ip_cidr)
            except KeyError:
                print('\t\t[+] CIDR: {}/{}'.format(ip['v6prefix'], ip['length']))
                ip_cidr = ''.join((ip['v6prefix'], '/', str(ip['length'])))
                ipv6_orgs_cidr.setdefault(orgs[count], []).append(ip_cidr)
        count += 1

def shodan_query(cidr_notated):
    print('\n[*] Searching for open ports on Shodan for discovered IPv4 CIDR notations...')
    api = shodan.Shodan(SHODAN_API_KEY)
    for ip_cidr in cidr_notated:
        try:
            hosts = api.search('net:'+ip_cidr)
        except shodan.exception.APIError:
            print('[-] Shodan query failed. Make sure your API key is correct.\n')
            exit(1)
        time.sleep(1.1)      #Shodan search is limited to 1 request per second
        if len(hosts['matches']) == 0:
            print('\n[*] No matches for {}'.format(ip_cidr))
        else:
            print('\n[*] Matches for {} (Only showing results for specified ports)'.format(ip_cidr)) if args.ports\
                else print('\n[*] Matches for {}'.format(ip_cidr))
        for content in hosts['matches']:
            if specific_ports:
                if str(content['port']) in ports:
                    writer(content,outfile=True) if args.outfile else writer(content)
            else:
                writer(content,outfile=True) if args.outfile else writer(content)

    if args.outfile:
        print('\n[*] Done! Results saved in {}\n'.format(args.outfile))
    else:
        print('\n[*] Done!\n')

def writer(item,outfile=False):
    if outfile == True:
        domains = item.get('domains')
        [len(domains) for domain in domains]
        total_chars = sum(len(domain) for domain in domains)
        if total_chars > 750:
            domain_write_check = 'List of domains too large, check {}_domains.txt for the list of domains for this ' \
                                 'address'.format(item['ip_str'])
            domains_outfile = open('{}_domains.txt'.format(item['ip_str']),'w')
            domains_outfile.write('\n'.join(domains))
            domains_outfile.close()
        else:
            domain_write_check = domains
        csv_writer.writerow(
            [item.get('ip_str'), item.get('port'), domain_write_check, item.get('os'), item.get('transport'),
             item.get('isp'), item.get('org'), item.get('data'), item.get('http',{}).get('title'),
             item.get('http',{}).get('server'), item.get('http',{}).get('waf')])
    print('\t[+] ' + item['ip_str'], item['port'], sep=':')

def print_orgs():
    re_company = re.sub(' +', '_', args.company)
    if len(orgs_cidr) != 0:
        print('\n[*] Discovered IPv4 CIDR notations for {}:'.format(args.company))
        ipv4_file = open('{}_ipv4.txt'.format(re_company),'w')
        for org, cidr in orgs_cidr.items():
            for item in range(len(cidr)):
                print('{}- {}'.format(org, cidr[item]))
                ipv4_file.write('{}- {}\n'.format(org,cidr[item]))
        print('\n[*] IPv4 ARIN results written to {}_ipv4.txt'.format(re_company))

    if len(ipv6_orgs_cidr) != 0:
        print('\n[*] Discovered IPv6 CIDR notations for {}:'.format(args.company))
        ipv6_file = open('{}_ipv6.txt'.format(re.sub(' +', '_', args.company)), 'w')
        for org, cidr in ipv6_orgs_cidr.items():
            for item in range(len(cidr)):
                print('{}- {}'.format(org, cidr[item]))
                ipv6_file.write('{}- {}\n'.format(org, cidr[item]))
        print('\n[*] IPv6 ARIN results written to {}_ipv6.txt'.format(re_company))

if __name__ == "__main__":
    main()