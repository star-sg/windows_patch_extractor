
import sys
import os
import subprocess
import pickle
import json

import shutil


from typing import Union, ByteString, Iterable

from dataclasses import dataclass
from tabulate import tabulate

import delta_patch

from micorsoft_api import *

from termcolor import colored, cprint

from pathlib import Path


WINSXS_DIR = r'C:\Windows\WinSxS'
LOCAL_MACHINE_SCAN_FILE: str = os.path.join(os.getenv('APPDATA'), 'WINSXS.pkl')

PLATFORMS = set(('x86', 'amd64', 'wow64', 'msil'))
BINARY_FILE_TYPE = set(('dll', 'exe', 'driver'))
UPDATE_FILE_TYPE = set(('normal', 'null', 'forward', 'reverse'))

def print_info(msg: str):
    prompt = colored('[INFO] ', 'green')
    print (prompt + msg)

def print_warning(msg: str):
    prompt = colored('[WARNING] ', 'yellow')
    print(prompt + msg)

def print_error(msg: str):
    prompt = colored('[ERROR] ', 'red')
    print(prompt + msg)

def debug_print(msg: str):
    prompt = colored('[DEBUG] ', 'blue')
    print(prompt + msg)

def is_valid_platform(platform: str):
    if platform not in PLATFORMS:
        print (PLATFORMS)
        raise Exception('Invalid platform')

def pardir(path: str):
    return os.path.normpath(os.path.join(path, os.path.pardir))

def run(cmd: str):
    print_info(f'Running {cmd}')
    subprocess.call(f'start /wait {cmd}', shell=True)

def expand(f, out_dir):
    expand_cmd = 'expand.exe -F:*'
    cmd = f'{expand_cmd} {f} {out_dir}'
    run(cmd)

def expand_psf(f: str, out_dir: str):
    old_out_dir = f.replace('.cab', '')
    expand_psf_cmd = 'PSFExtractor.exe'
    cmd = f'{expand_psf_cmd} {f}'
    run(cmd)
    os.rename(old_out_dir, out_dir)

def expand_everything(msu_file: str, out_dir: str):
    expand(msu_file, out_dir)

    for name in os.listdir(out_dir):
        fname = os.path.join(out_dir, name)
        child_dir = fname.replace('.', '_')

        if name == 'wsusscan.cab':
            print_warning('ignore wsusscan.cab')
            continue

        elif name.endswith('.cab'):
            if os.path.exists(fname.replace('.cab', '.psf')):
                print_info(f'Found {name} file')
                # PSFExtractor.exe will create a output directory for us
                expand_psf(fname, child_dir)
            else:
                os.makedirs(child_dir, exist_ok = True)
                expand(fname, child_dir)
        else:
            pass
            # print (f'ignore {name}')

@dataclass
class UpdateFile():
    path: str
    version: str
    platform: str
    type: str

    def __init__(self, file_type, path, ver=None, platform=None):
        assert(file_type in UPDATE_FILE_TYPE)
        self.path = path
        self.version = ver
        self.platform = platform
        self.type = file_type
        
class Scanner():
    def __init__(self):
        self.normal_dll: list[UpdateFile] = list()
        self.normal_driver: list[UpdateFile] = list()
        self.normal_exe: list[UpdateFile] = list()

        self.null_dll: list[UpdateFile] = list()
        self.null_driver: list[UpdateFile] = list()
        self.null_exe: list[UpdateFile] = list()

        self.forward_dll: list[UpdateFile] = list()
        self.forward_driver: list[UpdateFile] = list()
        self.forward_exe: list[UpdateFile] = list()

        self.reverse_dll: list[UpdateFile] = list()
        self.reverse_driver: list[UpdateFile] = list()
        self.reverse_exe: list[UpdateFile] = list()

    def search_null(self, fname:str, platform: str) -> Union[UpdateFile, None]:
        l: list[UpdateFile]
        if  fname.endswith('.dll'):
            l = self.null_dll
        elif fname.endswith('.exe'):
            l = self.null_exe
        elif fname.endswith('.sys'):
            l = self.null_driver

        f: UpdateFile
        for f in l:
            if fname.lower() == os.path.basename(f.path).lower() and f.platform == platform:
                return f
        
        return None

    def search_all_null(self, fname:str, platform: str, version: str, version_cmp: int) -> Iterable[UpdateFile]:
        l: Iterable[UpdateFile]
        if  fname.endswith('.dll'):
            l = self.null_dll
        elif fname.endswith('.exe'):
            l = self.null_exe
        elif fname.endswith('.sys'):
            l = self.null_driver

        def match(f: UpdateFile):
            if fname.lower() == os.path.basename(f.path).lower() and f.platform == platform and cmp_build_number(version, f.version)*version_cmp > 0:
                return True

        return filter(match, l)

    def search_reverse(self, fname: str, platform: str) -> Union[UpdateFile, None]:
        if  fname.endswith('.dll'):
            l = self.reverse_dll
        elif fname.endswith('.exe'):
            l = self.reverse_exe
        elif fname.endswith('.sys'):
            l = self.reverse_driver

        f: UpdateFile
        for f in l:
            if fname.lower() == os.path.basename(f.path).lower() and f.platform == platform:
                return f
        
        return None

    def search_all_reverse(self, fname:str, platform: str, version: str, version_cmp: int) -> Iterable[UpdateFile]:
        l: Iterable[UpdateFile]
        if  fname.endswith('.dll'):
            l = self.reverse_dll
        elif fname.endswith('.exe'):
            l = self.reverse_exe
        elif fname.endswith('.sys'):
            l = self.reverse_driver

        def match(f: UpdateFile):
            if fname.lower() == os.path.basename(f.path).lower() and f.platform == platform and cmp_build_number(version, f.version)*version_cmp > 0:
                return True

        return filter(match, l)

    def search_forward(self, fname: str, platform: str) -> Union[UpdateFile, None]:
        if  fname.endswith('.dll'):
            l = self.forward_dll
        elif fname.endswith('.exe'):
            l = self.forward_exe
        elif fname.endswith('.sys'):
            l = self.forward_driver

        f: UpdateFile
        for f in l:
            if fname.lower() == os.path.basename(f.path).lower() and f.platform == platform:
                return f
        
        return None

    def search_all_forward(self, fname:str, platform: str, version: str, version_cmp: int) -> Iterable[UpdateFile]:
        l: Iterable[UpdateFile]
        if  fname.endswith('.dll'):
            l = self.forward_dll
        elif fname.endswith('.exe'):
            l = self.forward_exe
        elif fname.endswith('.sys'):
            l = self.forward_driver
            
        def match(f: UpdateFile):
            if fname.lower() == os.path.basename(f.path).lower() and f.platform == platform and cmp_build_number(version, f.version)*version_cmp > 0:
                return True

        return filter(match, l)

    def search_normal(self, fname: str, platform: str) -> Union[UpdateFile, None]:
        if  fname.endswith('.dll'):
            l = self.normal_dll
        elif fname.endswith('.exe'):
            l = self.normal_exe
        elif fname.endswith('.sys'):
            l = self.normal_driver

        f: UpdateFile
        for f in l:
            if fname.lower() == os.path.basename(f.path).lower() and f.platform == platform:
                return f
        
        return None

    def search_all_normal(self, fname:str, platform: str, func: callable) -> Iterable[UpdateFile]:
        l: Iterable[UpdateFile]
        if  fname.endswith('.dll'):
            l = self.normal_dll
        elif fname.endswith('.exe'):
            l = self.normal_exe
        elif fname.endswith('.sys'):
            l = self.normal_driver
            
        def match(f: UpdateFile):
            if fname.lower() == os.path.basename(f.path).lower() and f.platform == platform and func(f):
                return True

        return filter(match, l)

    def extract(self, fname: str, extract_dir: str, platform: str ='amd64') -> tuple[ByteString, str]:
        f = self.search_normal(fname, platform)
        if f:
            print_info(f'Normal file found at {f.path}')
            return (read_file(f.path), f.version)

        f = self.search_null(fname, platform)
        if f:
            print_info(f'Null file found at {f.path}')
            return (delta_patch.apply_patch(read_file(f.path), bytearray(), False), f.version)

        f = self.search_forward(fname, platform)
        if f:
            print_info(f'Forward file found at {f.path}')
            print_info(f'Extracting base_file from local machine')
            base_file = extract_local_basefile(fname, platform)
            forward_file = read_file(f.path)
            print_info(f'Applying forward_file to base_file')
            return (delta_patch.apply_patch(base_file, forward_file, False), f.version)

        f = self.search_reverse(fname, platform)
        if f:
            print_info(f'Ignore reverse file found at {f.path}')
        print_error(f'Failed to find {platform} {fname} in {extract_dir}')
        raise Exception('extract failed\n')

    def found_null_dll(self, path, ver=None, platform=None):
        self.null_dll.append(UpdateFile('null', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_null_driver(self, path, ver=None, platform=None):
        self.null_driver.append(UpdateFile('null', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_null_exe(self, path, ver=None, platform=None):
        self.null_exe.append(UpdateFile('null', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_normal_dll(self, path, ver=None, platform=None):
        self.normal_dll.append(UpdateFile('normal', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_normal_driver(self, path, ver=None, platform=None):
        self.normal_driver.append(UpdateFile('normal', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_normal_exe(self, path, ver=None, platform=None):
        self.normal_exe.append(UpdateFile('normal', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_forward_dll(self, path, ver=None, platform=None):
        self.forward_dll.append(UpdateFile('forward', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_forward_driver(self, path, ver=None, platform=None):
        self.forward_driver.append(UpdateFile('forward', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_forward_exe(self, path, ver=None, platform=None):
        self.forward_exe.append(UpdateFile('forward', path, ver, platform))

    def found_reverse_dll(self, path, ver=None, platform=None):
        self.reverse_dll.append(UpdateFile('reverse', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_reverse_driver(self, path, ver=None, platform=None):
        self.reverse_driver.append(UpdateFile('reverse', path, ver, platform))
        # print (f'found_normal_dll: {path}')

    def found_reverse_exe(self, path, ver=None, platform=None):
        self.reverse_exe.append(UpdateFile('reverse', path, ver, platform))

    def found_sub_cab(self, fname):
        pass
        # print (f'ignore {fname}')

    def found_manifest(self, fname):
        pass
        # print (f'ignore {fname}') 

    def found_forward_dir(self, path, ver, platform):
        for name in os.listdir(path):
            sub_path = os.path.join(path, name)
            self.maybe_forward_executeable(sub_path, ver, platform)

    def found_reverse_dir(self, path, ver, platform):
        for name in os.listdir(path):
            sub_path = os.path.join(path, name)
            self.maybe_reverse_executable(sub_path, ver, platform)

    def found_null_dir(self, path, ver, platform):
        for name in os.listdir(path):
            sub_path = os.path.join(path, name)
            self.maybe_null_executable(sub_path, ver, platform)

    def maybe_forward_executeable(self, path, ver, platform):
        name = os.path.basename(path)
        if name.endswith('.dll'):
            self.found_forward_dll(path, ver, platform)
            return True
        elif name.endswith('.sys'):
            self.found_forward_driver(path, ver, platform)
            return True
        elif name.endswith('.exe'):
            self.found_forward_exe(path, ver, platform)
            return True
        return False 

    def maybe_null_executable(self, path, ver=None, platform=None):
        name = os.path.basename(path)
        if name.endswith('.dll'):
            self.found_null_dll(path, ver, platform)
            return True
        elif name.endswith('.sys'):
            self.found_null_driver(path, ver, platform)
            return True
        elif name.endswith('.exe'):
            self.found_null_exe(path, ver, platform)
            return True
        return False

    def maybe_reverse_executable(self, path, ver=None, platform=None):
        name = os.path.basename(path)
        if name.endswith('.dll'):
            self.found_reverse_dll(path, ver, platform)
            return True
        elif name.endswith('.sys'):
            self.found_reverse_driver(path, ver, platform)
            return True
        elif name.endswith('.exe'):
            self.found_reverse_exe(path, ver, platform)
            return True
        return False

    def maybe_normal_executable(self, path, ver=None, platform=None):
        name = os.path.basename(path)
        if name.endswith('.dll'):
            self.found_normal_dll(path, ver, platform)
            return True
        elif name.endswith('.sys'):
            self.found_normal_driver(path, ver, platform)
            return True
        elif name.endswith('.exe'):
            self.found_normal_exe(path, ver, platform)
            return True
        return False

    def maybe_delta_dir(self, path):
        dirname = os.path.basename(path)
        parts = dirname.split('_')
        try:
            platform = parts[0]
        except IndexError:
            # print(f'not delta_dir {dirname}')
            return
        
        # print (dirname)
        s = re.search(r'_([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)_', dirname)
        if s == None:
            # print(f'not delta_dir {dirname}')
            return 
        ver = s.group(1)

        if platform not in PLATFORMS:
            return
        
        # print (ver, platform)
        for name in os.listdir(path):
            sub_path = os.path.join(path, name)
            if name == 'f':
                self.found_forward_dir(sub_path, ver, platform)
            elif name == 'r':
                self.found_reverse_dir(sub_path, ver, platform)
            elif name == 'n':
                self.found_null_dir(sub_path, ver, platform)
            elif self.maybe_normal_executable(sub_path, ver, platform):
                pass
            else:
                pass

    def scan_child_dir(self, path: str):
        for name in os.listdir(path):
            sub_path = os.path.join(path, name)
            if self.maybe_null_executable(sub_path):
                pass
            elif name.endswith('.cab'):
                self.found_sub_cab(sub_path)
            elif name.endswith('.manifest'):
                self.found_manifest(sub_path)
            elif os.path.isdir(sub_path):
                self.maybe_delta_dir(sub_path)

    def summary(self):
        print(tabulate(self.normal_dll))
        print(tabulate(self.normal_driver))
        print(tabulate(self.normal_exe))

        print(tabulate(self.null_dll))
        print(tabulate(self.null_driver))
        print(tabulate(self.null_exe))

        print(tabulate(self.forward_dll))
        print(tabulate(self.forward_driver))
        print(tabulate(self.forward_exe))

        print(tabulate(self.reverse_dll))
        print(tabulate(self.reverse_driver))
        print(tabulate(self.reverse_exe))

def read_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

def extract_local_basefile(filename: str, platform: str) -> ByteString:
    is_valid_platform(platform)

    scanner = Scanner()
    scanner.scan_child_dir(WINSXS_DIR)

    l: list[UpdateFile]
    if filename.endswith('.dll'):
        l = scanner.reverse_dll
    elif filename.endswith('.exe'):
        l = scanner.reverse_exe
    elif filename.endswith('.sys'):
        l = scanner.reverse_driver
    else:
        raise Exception('This file type is not supported')

    found = False
    reverse_file: UpdateFile
    for reverse_file in l:
        path = reverse_file.path
        if os.path.basename(path).lower() == filename.lower() and reverse_file.platform == platform:
            print_info(f'Reverse file found {path}')
            found = True
            break
    
    if not found:
        print_error(f'Can\'t find reverse file for {filename}')
        raise Exception('extract_base_file error')

    # there should be a normal file in this folder too
    dirname = os.path.normpath(os.path.join(os.path.dirname(reverse_file.path), os.path.pardir))
    for name in os.listdir(dirname):
        if name.lower() == filename.lower():
            normal_file_path = os.path.join(dirname, name)
            print_info(f'Normal file found {normal_file_path}')

    print_info('Applying delta_patch')
    base_file = delta_patch.apply_patch(read_file(normal_file_path), read_file(reverse_file.path), False)
    return base_file

def do_scan_local() -> Scanner:
    scanner = Scanner()
    # scan WINSX_DIR for local versions of updates
    scanner.scan_child_dir(WINSXS_DIR)
    return scanner

def do_scan(scan_dir: str):
    print_info(f'Scanning {scan_dir}')

    if scan_dir == WINSXS_DIR:
        scan_file_path = LOCAL_MACHINE_SCAN_FILE
    else:
        scan_file_path = os.path.join(scan_dir, SCAN_FILE_NAME)
    if scan_file_exists(scan_dir):
        with open(scan_file_path, 'rb') as f:
            try:
                print_info(f'Using cached result')
                scanner = pickle.load(f)
            except:
                print_error(f'{scan_file_path} corrupted')
    else:
        scanner = Scanner()
        # scan an extracted msu file and save scan result in the same folder
        
        for name in os.listdir(scan_dir):
            path = os.path.join(scan_dir, name)
            if os.path.isdir(path):
                scanner.scan_child_dir(path)
        with open(scan_file_path, 'wb') as f:
            pickle.dump(scanner, f)

    return scanner

SCAN_FILE_NAME = 'scan.pkl'
def scan_file_exists(dir: str):
    return os.path.exists(os.path.join(dir, SCAN_FILE_NAME))

if __name__ == '__main__':
    action = sys.argv[1]

    if action == '-expand':
        # expand a msu file
        msu_file = sys.argv[2]
        assert(os.path.exists(msu_file))
        
        out_dir = os.path.join(os.path.dirname(msu_file), 'expand')
        
        # create output directory if doesn't exist
        if not os.path.exists(out_dir):
            print (f'create {out_dir}')
            os.makedirs(out_dir, exist_ok = True)

        expand_everything(msu_file, out_dir)

    elif action == '-extract':
        fname = sys.argv[2]
        platform = sys.argv[3]
        expand_dir = sys.argv[4]
        out_dir = pardir(expand_dir)

        assert(os.path.exists(expand_dir))
        assert(os.path.exists(out_dir))

        is_valid_platform(platform)

        update_scanner = do_scan(expand_dir)
        file_data, version = update_scanner.extract(fname, expand_dir, platform)

        out_path = os.path.join(out_dir, fname)
        with open(out_path, 'wb') as f:
            f.write(file_data)

        print_info(f'File version {version} written to {out_path}')

    elif action == '-scan':
        scan_dir = sys.argv[2]
        update_scanner = do_scan(scan_dir)
        update_scanner.summary()

    elif action == '-local':
        do_scan_local()

    elif action == '-l':
        cprint('List of products', 'green')
        print(json.dumps(get_products(), sort_keys=True, indent=4))

    elif action == '-cve':
        cve = sys.argv[2].upper()
        product_id = int(sys.argv[3])

        update = get_update_for_product_id(search_cve(cve), product_id)
        if update == None:
            raise Exception(f'can not find update for {product_id}')

        skb = get_security_update_kbarticle(update)
        fixed_build_number = skb['fixedBuildNumber']
        release_number = get_update_release_number(update)

        if not is_same_os(fixed_build_number, get_build_number()):
            cprint('[!WARNING] product_id doesn\'t match local machine', 'yellow')

        cprint(f'Security update {release_number} for {cve} on {get_product_name(product_id)}', 'green')
        print(json.dumps(skb, sort_keys=True, indent=4))

    elif action == '-diff':
        fname = sys.argv[2]
        platform = sys.argv[3]
        expand_dir = sys.argv[4]

        out_dir = pardir(expand_dir)

        print_info(f'Using platform {platform}')

        # scan expand_dir for fname requested
        update_scanner = do_scan(expand_dir)
        file_data, version = update_scanner.extract(fname, expand_dir, platform)
        print_info(f'Found {fname} version: {version} in {expand_dir}')

        # scan local machine for the same file with a lower version
        print_info(f'Searching for older verion of {fname} in {WINSXS_DIR}')
        local_scanner = do_scan_local()

        def func(f:UpdateFile):
            if cmp_build_number(f.version, version) < 0:
                return True

        m: Iterable[UpdateFile] = list(local_scanner.search_all_normal(fname, platform, func))
        if len(m) == 0:
            print_error('Can\'t find local file with smaller version')
            raise Exception('diff failed')
        else:
            print_info('Normal local files with smaller version found:')
            print (tabulate(m))
            normal_file = m[0]

            with open(os.path.join(out_dir, fname) + '_2', 'wb') as f:
                f.write(file_data)
            
            print_info(f'Copying {normal_file.path} to {out_dir}')
            shutil.copy(normal_file.path, os.path.join(out_dir, fname) + '_1')


    else:
        print_error(f'invalid action: {action}')

        