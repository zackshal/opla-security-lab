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

def snapshot():
    link=run('ip','-j','link','show','dev','ens3')[0].get('xdp',{})
    active=link.get('attached','off')!='off'
    if not active: return dict(loaded=0,mode='off',**{k:0 for k in KEYS})
    prog=run('bpftool','-j','prog','show','pinned',PIN+'/program')
    if isinstance(prog,list): prog=prog[0]
    attached=link.get('prog',{}).get('id',link.get('prog_id'))
    if attached is None or int(attached)!=int(prog['id']):
        raise ValueError('Счётчики не принадлежат программе на ens3')
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
    return dict(loaded=1,mode=link.get('attached','unknown'),**stats)

if __name__=='__main__':
    try: print(json.dumps(snapshot()))
    except (OSError,ValueError,subprocess.SubprocessError) as e:
        print(str(e),file=sys.stderr);sys.exit(1)
