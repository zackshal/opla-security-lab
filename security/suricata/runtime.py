#!/usr/bin/env python3
import re
import subprocess
import sys
from nft_policy import OWNER_COMMENT, delete_owned_table, replace_table

def main():
    mode, interface = sys.argv[1:]
    if mode not in ['ids', 'ips'] or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
        raise ValueError('Invalid runtime arguments')
    if mode == 'ids':
        delete_owned_table()
        return
    rules = '''table inet opla_ips {
 comment "''' + OWNER_COMMENT + '''"
 chain input { type filter hook input priority 10; policy accept;
  iifname "__IF__" tcp dport 80 counter queue num 42
 }
 chain output { type filter hook output priority 10; policy accept;
  oifname "__IF__" tcp sport 80 counter queue num 42
 }
}
'''.replace('__IF__', interface)
    replace_table(rules)

if __name__ == '__main__':
    main()
