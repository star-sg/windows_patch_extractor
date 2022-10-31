from distutils.command.install_egg_info import safe_name
import re
import json
import requests

import tqdm

import winreg
from termcolor import colored, cprint


import os

# $orderBy=releaseDate desc&$filter=productFamilyId in ('100000010') and productId in ('12086') and severityId in ('100000000') and impactId in ('0','100000000','100000001','100000002','100000003','100000004','100000005','100000006','100000007','100000008','100000009') and platformId in ('11926') and (releaseDate gt 2022-09-14T00:00:00 08:00) and (releaseDate lt 2022-10-15T23:59:59 08:00)

# this code one day will comeback and haunt me to dead
PRODUCTS = {
    10378: 'Windows Server 2012',
    10379: 'Windows Server 2012 (Server Core installation)',
    10051: 'Windows Server 2008 R2 for x64-based Systems Service Pack 1',
    9344: 'Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)',
    10287: 'Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)',
    9312: 'Windows Server 2008 for 32-bit Systems Service Pack 2',
    9312: 'Windows RT 8.1',
    10482: 'Windows 8.1 for x64-based systems',
    10481: 'Windows 8.1 for 32-bit systems',
    10048: 'Windows 7 for x64-based Systems Service Pack 1',
    10047: 'Windows 7 for 32-bit Systems Service Pack 1',
    10855: 'Windows Server 2016 (Server Core installation)',
    10816: 'Windows Server 2016',
    10853: 'Windows 10 Version 1607 for x64-based Systems',
    10852: 'Windows 10 Version 1607 for 32-bit Systems',
    10735: 'Windows 10 for x64-based Systems',
    10729: 'Windows 10 for 32-bit Systems',
    11930: 'Windows 10 Version 21H2 for ARM64-based Systems',
    11572: 'Windows Server 2019 (Server Core installation)',
    11571: 'Windows Server 2019', 
    11570: 'Windows 10 Version 1809 for ARM64-based Systems', 
    11569: 'Windows 10 Version 1809 for x64-based Systems', 
    10483: 'Windows Server 2012 R2', 
    10543: 'Windows Server 2012 R2 (Server Core installation)', 
    10049: 'Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)', 
    9318: 'Windows Server 2008 for x64-based Systems Service Pack 2', 
    11568: 'Windows 10 Version 1809 for 32-bit Systems', 
    11801: 'Windows 10 Version 20H2 for 32-bit Systems', 
    12086: 'Windows 11 Version 22H2 for x64-based Systems', 
    11923: 'Windows Server 2022', 
    11897: 'Windows 10 Version 21H1 for ARM64-based Systems', 
    11931: 'Windows 10 Version 21H2 for x64-based Systems', 
    11924: 'Windows Server 2022 (Server Core installation)', 
    11929: 'Windows 10 Version 21H2 for 32-bit Systems', 
    11898: 'Windows 10 Version 21H1 for 32-bit Systems', 
    11896: 'Windows 10 Version 21H1 for x64-based Systems', 
    11927: 'Windows 11 for ARM64-based Systems', 
    11926: 'Windows 11 for x64-based Systems', 
    11800: 'Windows 10 Version 20H2 for x64-based Systems', 
    11802: 'Windows 10 Version 20H2 for ARM64-based Systems', 
    12085: 'Windows 11 Version 22H2 for ARM64-based Systems', 
}

def get_products():
    return PRODUCTS

def get_product_name(product_id):
    return PRODUCTS[product_id]

def cmp_build_number(a, b):
    def weighted_sum(parts):
        r = 0
        for i, p in enumerate(parts):
            r += int(p)*(10**(4-i))
        return r

    sa = weighted_sum(a.split('.'))
    sb = weighted_sum(b.split('.'))

    return sa-sb

def is_same_os(a, b):
    partsa = a.split('.')
    partsb = b.split('.')

    if partsa[0] == partsb[0] and partsa[1] == partsb[1]:
        return True
    return False

def get_build_number():
    k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion')

    major = winreg.QueryValueEx(k, 'CurrentMajorVersionNumber')
    minor = winreg.QueryValueEx(k, 'CurrentMinorVersionNumber')
    build_number = winreg.QueryValueEx(k, 'CurrentBuildNumber')
    ubr = winreg.QueryValueEx(k, 'UBR')

    return f'{major}.{minor}.{build_number}.{ubr}'

def is_valid_product_id(product_id):
    if product_id not in PRODUCTS:
        cprint('[ERROR] Invalid product_id', 'red')
        print(json.dumps(PRODUCTS, sort_keys=True, indent=4))
        raise Exception('Invalid product_id')
        
def download_page(url, headers=None):
    r = requests.get(url, headers=headers)
    return r.text

def search_cve(cve):
    cve = cve.upper()

    burp0_url = "https://api.msrc.microsoft.com:443/sug/v2.0/en-GB/affectedProduct?%24filter=cveNumber+eq+%27{}%27".format(cve)
    burp0_headers = {"Sec-Ch-Ua": "\"Not;A=Brand\";v=\"99\", \"Chromium\";v=\"106\"", "Pragma": "no-cache", "Sec-Ch-Ua-Mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36", "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Cache-Control": "no-cache", "Sec-Ch-Ua-Platform": "\"Windows\"", "Accept": "*/*", "Origin": "https://msrc.microsoft.com", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://msrc.microsoft.com/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"}
    r = download_page(burp0_url, burp0_headers)
    d = json.loads(r)['value']
    return d

def _get_update_download_url(update_id):
    burp0_url = "https://catalog.update.microsoft.com:443/DownloadDialog.aspx"
    burp0_headers = {"Cache-Control": "max-age=0", "Sec-Ch-Ua": "\"Not;A=Brand\";v=\"99\", \"Chromium\";v=\"106\"", "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Windows\"", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36", "Origin": "https://catalog.update.microsoft.com", "Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"}
    burp0_data = {"updateIDs": "[{\"size\":0,\"languages\":\"\",\"uidInfo\":\"##UPDATE_ID##\",\"updateID\":\"##UPDATE_ID##\"}]\r\n\r\n".replace('##UPDATE_ID##', update_id)}
    r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
    s = re.search(r"downloadInformation\[0\]\.files\[0\]\.url = '([^']+)'", r.text)
    url = s.group(1)
    return url

def _download_file(url, out_file_path):
    CHUNK_SIZE = 1<<20
    with requests.get(url, stream=True) as r:
        total_size_in_mb =  int(r.headers['content-length'])/CHUNK_SIZE
        r.raise_for_status()
        with open(out_file_path, 'wb') as f:
            with tqdm.trange(int(total_size_in_mb), unit='MB') as pbar:
                for chunk in r.iter_content(chunk_size=CHUNK_SIZE): 
                    # If you have chunk encoded response uncomment if
                    # and set chunk_size parameter to None.
                    #if chunk: 
                    pbar.update(1)
                    f.write(chunk)

def get_update_for_product_id(updates, product_id):
    is_valid_product_id(product_id)
    for update in updates:
        if update['productId'] == product_id:
            return update
    return None

# updates contains update for multiple product_id
# each update has multiple kbarticles
def get_security_update_kbarticle(update):
    for update in update['kbArticles']:
        if update['downloadName'] == 'Security Update' or update['downloadName'] == 'Security Only':
            return update
    raise Exception('can not find Security Update in kbArticles')

def get_update_release_number(update):
    return update['releaseNumber']

def download_security_update(cve, product_id, out_file_path):
    updates = search_cve(cve)
    security_update_kbarticle = get_security_update_kbarticle(updates, product_id)
    url = security_update_kbarticle['downloadUrl']

    anchor_regex = re.compile(r"<a id='([a-z0-9\-]+)_link'[^>]+>([^<]+)<\/a>", re.DOTALL)
    anchor_tags = anchor_regex.findall(download_page(url))
    
    if len(anchor_tags) == 0:
        raise Exception('can not find updates anchor tags')

    try:
        product_name = PRODUCTS[product_id]
    except KeyError:
        raise Exception(f'Invalid product_id valid products {PRODUCTS}')

    found = False
    for tag in anchor_tags:
        update_id = tag[0].strip()
        update_name = tag[1].strip()
        
        if update_name.find(product_name) != -1:
            found = True
            break
    
    if not found:
        print (anchor_tags)
        raise Exception('shit happened')

    # print (update_name, update_id)
    url = _get_update_download_url(update_id)
    _download_file(url, out_file_path)


if __name__ == '__main__':
    download_security_update('CVE-2022-38044', 11800, r'e:\CVE-2022-38044.msu')