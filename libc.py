# 待完成的组件：
# 1. dbg 版本下载，恢复调试符号
# 2. 无libc.so直接通过二进制文件获取libc版本
# 3. 自动尝试所有的libc，patch后能运行则成功，用绿色表示，不能则失败，用红色表示，最后输出所有libc版本，并用颜色区分哪些可以patch
#    并且默认选择第一个可以patch的libc版本来patch

from colorama import init, Fore, Back, Style
from bs4 import BeautifulSoup
from pwn import *
import argparse
import requests
import sys
import os

context(os='linux',arch='amd64',log_level='critical')

def create_directory_if_not_exist(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def detect_libc(addr):
    print(Fore.GREEN + '\n[+] Confirming Libc Version' + Style.RESET_ALL)
    items = addr.split(',')
    result = [(items[i], items[i+1]) for i in range(0, len(items), 2)]
    print(result)
    
    url = f"https://libc.blukat.me/?q="
    for func, addr in result:
        url += f"{func}%3A{addr}%2C"
    # print(url)
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    lib_items = soup.find_all('a', class_='lib-item')
    i = 0
    if lib_items:
        for lib_item in lib_items:
            i += 1
            print(Fore.BLUE + f'[+] {i}. libc version for this binary is {lib_item.text.strip()}' + Style.RESET_ALL)
        return lib_items
    else:
        print(Fore.RED + "[x] Libc names not found in response." + Style.RESET_ALL)
        return None
    

def auto_patch(binary, libc):   
    # ====================================Confirming Libc Version======================================
    libc = ELF(libc)

    puts_hex = format(libc.sym['puts'] & 0xfff, 'X')
    read_hex = format(libc.sym['read'] & 0xfff, 'X')
    printf_hex = format(libc.sym['printf'] & 0xfff, 'X') 
    
    lib_items = detect_libc(f"puts,{puts_hex},read,{read_hex},printf,{printf_hex}")
    lib_item_version = int(input(Fore.GREEN + '[+] Plz pick libc version:' + Style.RESET_ALL)) - 1
    if lib_item_version >= len(lib_items):
        print(Fore.RED + "[x] Invalid libc version selected." + Style.RESET_ALL)
        return
    
    # =====================================Downloading & Extracting======================================
    print(Fore.GREEN + '\n[+] Downloading & Extracting' + Style.RESET_ALL)
    create_directory_if_not_exist("./debs")
    create_directory_if_not_exist("./libs")

    lib_item = lib_items[lib_item_version].text.strip()
    if os.path.exists(f"./debs/{lib_item}.deb"):
        print(Fore.BLUE + '[+] Libc already downloaded' + Style.RESET_ALL)
        if os.path.exists(f"./libs/{lib_item}"):
            print(Fore.BLUE + '[+] Libc already extracted' + Style.RESET_ALL)
        else:
            os.system(f"./extract {lib_item}.deb ./libs/{lib_item}")
            print(Fore.BLUE + '[+] Libc extracted' + Style.RESET_ALL)
    else:
        lib_item = lib_items[0].text.strip()
        url = f"https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/{lib_item}.deb"
        os.system(f"wget {url} -O ./debs/{lib_item}.deb")
        os.system(f"./extract {lib_item}.deb ./libs/{lib_item}")
    print(Fore.YELLOW + '[+] Downloaded & Extracted' + Style.RESET_ALL)

    # =====================================Patching Binary============================================
    print(Fore.GREEN + '\n[+] Patching Binary' + Style.RESET_ALL)

    cmd  = f"patchelf --set-interpreter ./libs/{lib_item}/ld-linux-x86-64.so.2 "
    cmd += f"--set-rpath ./libs/{lib_item} {binary} "
    cmd += f"--replace-needed libc.so.6 ./libs/{lib_item}/libc.so.6 {binary}"
    os.system(cmd)

    print(Fore.YELLOW + '[+] Patch Succeeded!' + Style.RESET_ALL)


# =================================================================================================
if __name__ == '__main__':
    print(Fore.GREEN + '[+] dealing with arguments' + Style.RESET_ALL)
    parser = argparse.ArgumentParser('Auto Patching\n')
    parser.add_argument('-b', '--binary', type=str, help='File tp Patch')
    parser.add_argument('-l', '--libc', type=str, help='Libc to use for confirming version')
    parser.add_argument('--addr', type=str, 
                        help='Address to leak libc version. \
                                Format: <function_name1>,<address1>,<function_name2>,<address2>,...'
                        )
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    
    binary = args.binary
    libc = args.libc
    addr = args.addr

    print(Fore.YELLOW + '[+] Arguments done' + Style.RESET_ALL)
    if addr:
        detect_libc(addr)
    else:
        auto_patch(binary, libc)