#!/usr/bin/env python3
"""Один снимок pinned maps. trace_pipe не читаем: он общий и разрушающий."""
import json
from pathlib import Path
import subprocess
import sys

PIN='/sys/fs/bpf/opla'
KEYS=['syn','pass','drop','map_full','fragment_drop']

def number(value):
    if isinstance(value,int): return value
    if isinstance(value,str): return int(value,0)
    if isinstance(value,list):
        raw=bytes(int(x,0) if isinstance(x,str) else x for x in value)
        return int.from_bytes(raw,sys.byteorder)
    raise ValueError(f'Неподдерживаемый формат bpftool: {value!r}')

def run(*args):
    return json.loads(subprocess.check_output(args,text=True,timeout=5))

def attachment_mode(link, program_id):
    """iproute2 может возвращать attached строкой или списком программ."""
    labels = {1: 'native', 2: 'generic', 3: 'offload'}
    raw = link.get('attached')
    fallback = {'drv': 'native', 'native': 'native',
                'skb': 'generic', 'generic': 'generic', 'hw': 'offload'}
    candidates = [link]
    if isinstance(raw, list):
        candidates.extend(entry for entry in raw if isinstance(entry, dict))
    for entry in candidates:
        found = entry.get('prog', {}).get('id', entry.get('prog_id'))
        if found is not None and int(found) == int(program_id):
            code = entry.get('mode', link.get('mode'))
            if code in labels:
                return labels[code]
            if isinstance(raw, str) and raw in fallback:
                return fallback[raw]
    raise ValueError('Режим прикреплённой программы не определён')

def snapshot():
    link=run('ip','-j','link','show','dev','ens3')[0].get('xdp',{})
    active=bool(link) and link.get('attached', 'off') not in ('off', 0)
    if not active: return dict(loaded=0,mode='off',**{k:0 for k in KEYS})
    prog=run('bpftool','-j','prog','show','pinned',PIN+'/program')
    if isinstance(prog,list): prog=prog[0]
    mode=attachment_mode(link, prog['id'])
    entries=run('bpftool','-j','map','dump','pinned',PIN+'/maps/xdp_stats')
    stats={k:0 for k in KEYS}
    for entry in entries:
        index=number(entry['key'])
        if not 0<=index<len(KEYS): raise ValueError('Неизвестный индекс счётчика')
        if 'values' in entry:
            value=sum(number(v['value']) for v in entry['values'])
        elif 'value' in entry: value=number(entry['value'])
        else: raise ValueError('Нет значения счётчика')
        stats[KEYS[index]]=value
    return dict(loaded=1,mode=mode,**stats)

if __name__=='__main__':
    try: print(json.dumps(snapshot()))
    except (OSError,ValueError,subprocess.SubprocessError) as e:
        print(str(e),file=sys.stderr);sys.exit(1)
