#!/usr/bin/env python3
import re
import subprocess
import sys

def main():
    mode, interface = sys.argv[1:]
    if mode not in ['ids', 'ips'] or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
        raise ValueError('Invalid runtime arguments')
    exists = subprocess.run(['nft', 'list', 'table', 'inet', 'opla_ips'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    rules = 'delete table inet opla_ips\n' if exists else ''
    if mode == 'ips':
        rules += '''table inet opla_ips {
 chain input { type filter hook input priority 10; policy accept;
  iifname "__IF__" tcp dport 80 counter queue num 42
 }
 chain output { type filter hook output priority 10; policy accept;
  oifname "__IF__" tcp sport 80 counter queue num 42
 }
}
'''.replace('__IF__', interface)
    if rules:
        subprocess.run(['nft', '--check', '-f', '-'], input=rules, text=True, check=True)
        subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)

if __name__ == '__main__':
    main()
