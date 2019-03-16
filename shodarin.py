#!/usr/bin/env python3

import requests
import argparse
import shodan
import re
import csv
import time
from bs4 import BeautifulSoup

SHODAN_API_KEY = ''
ARIN_SEARCH_URL = 'https://whois.arin.net/ui/query.do'
ARIN_RDAP_URL = 'https://rdap.arin.net/registry/ip/'

nets = []
orgs = []
cidrs = []

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
parser.add_argument('-o', '--outfile', help='(Recommended) Name of CSV output file for Shodan results')
parser.add_argument('-w', '--wildcard', action='store_true', help='Perform a wildcard search. This will search using '
                                                                  '"*company name*" instead of just "company name". '
                                                                  'Not recommended for smaller company names')
parser.add_argument('-a', '--arin', action='store_true', help='Skip Shodan lookup and only output the '
                                                              'discovered CIDR notations from ARIN')
args = parser.parse_args()

if args.outfile:
    csv_file = open(args.outfile,'w',encoding='utf-8',newline='')
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(['IP Address','Port','Transport','ISP','Organization','Data','HTML Title'])

def main():
    if not args.arin:
        if len(SHODAN_API_KEY) == 0:
            print('[!] Shodan API key is missing! You need to fill in your key before doing Shodan queries!')
            exit(1)
        query(args.company)
        shodan_query(cidrs)
    else:
        query(args.company)
        print('\n[*] Discovered CIDR notations for {}:\n'.format(args.company))
        if len(cidrs) != 0:
            for ip_cidr in cidrs: print(ip_cidr)
        else:
            print('[-] No discovered CIDR notations')
        print('\n[*] Done!')

def query(company):
    count = 0
    company = '*'+company+'*' if args.wildcard else company
    data = {
        'advanced': 'true',
        'q': company,
        'r': 'ORGANIZATION'
    }
    print('[*] Searching ARIN for {}...\n'.format(company))
    r = requests.post(ARIN_SEARCH_URL,data=data)
    soup = BeautifulSoup(r.text,"html.parser")

    if 'could not be found' in soup.text:
        print('[-] Company not found. Try searching with wildcard (-w).')
        exit(1)
    elif soup.handle:
        orgs.append(''.join((soup.find_all('name')[1].string,' (',soup.find('handle').string,') ')))
        nets.append(soup.ref.string+'/nets')
    else:
        names = soup.find_all('td')
        for name in names:
            orgs.append(re.sub(' +',' ',name.text))
            nets.append(name.a['href']+'/nets')

    for url in nets:
        print('[*] Checking ' + orgs[count] + 'for netblocks...')
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "html.parser")
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
                    cidrs.append(''.join((ip['v4prefix'],'/',str(ip['length']))))
            except KeyError:
                for ip in block_json['cidr0_cidrs']:
                    print('\t\t[+] CIDR: {}/{}'.format(ip['v6prefix'], ip['length']))
        count += 1

def shodan_query(cidr_notated):
    results = 0
    print('\n[*] Searching for open ports on Shodan for discovered CIDR notations...')
    api = shodan.Shodan(SHODAN_API_KEY)
    for ip_cidr in cidr_notated:
        try:
            hosts = api.search('net:'+ip_cidr)
        except shodan.exception.APIError:
            print('[-] Shodan query failed. Make sure your API key is correct.')
            exit(1)
        time.sleep(1.1)      #Shodan search is limited to 1 request per second
        if len(hosts['matches']) == 0:
            print('\n[*] No matches for {}'.format(ip_cidr))
        else:
            print('\n[*] Matches for {}'.format(ip_cidr))
        for content in hosts['matches']:
            if args.outfile:
                if 'http' not in content or content['http']['title'] is None:
                    csv_writer.writerow(
                        [content['ip_str'], content['port'], content['transport'], content['isp'], content['org'], content['data'],
                         'N/A'])
                else:
                    csv_writer.writerow(
                        [content['ip_str'], content['port'], content['transport'], content['isp'], content['org'], content['data'],
                         content['http']['title']])
                print('\t[+] ' + content['ip_str'], content['port'], sep=':')
            else:
                print('\t[+] '+content['ip_str'],content['port'],sep=':')
    if args.outfile:
        print('\n[*] Done! Results saved in {}\n'.format(args.outfile))
    else:
        print('\n[*] Done!\n')

if __name__ == "__main__":
    main()