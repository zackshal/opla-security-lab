#!/usr/bin/env python3
"""SSH-снимок -> журнал JSONL -> Zabbix trapper. Запускается на хосте."""
import argparse
from collections import deque
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'bin'))
from state import load
from catalog import METRICS, item_key

def collect(ip,lab):
    cmd=['ssh','-i',os.environ.get('SSH_KEY',str(Path.home()/'.ssh/id_ed25519')),
         '-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=accept-new',
         '-o',f'UserKnownHostsFile={lab}/known_hosts',f'student@{ip}',
         'sudo python3 /tmp/xdp-build/collect.py']
    result=subprocess.run(cmd,capture_output=True,text=True,timeout=10,check=True)
    data=json.loads(result.stdout)
    if any(type(data.get(k)) is not int or data[k]<0 for k in METRICS):
        raise ValueError('Некорректный снимок метрик')
    if not isinstance(data.get('mode'), str):
        raise ValueError('Режим XDP должен быть строкой; обновите collect.py на victim')
    return data

def recv_exact(sock,n):
    result=b''
    while len(result)<n:
        chunk=sock.recv(n-len(result))
        if not chunk: raise OSError('Zabbix закрыл соединение')
        result+=chunk
    return result

def send(records,host='127.0.0.1',port=10051):
    body=json.dumps({'request':'sender data','data':records}).encode()
    with socket.create_connection((host,port),timeout=5) as sock:
        sock.sendall(b'ZBXD\x01'+struct.pack('<Q',len(body))+body)
        head=recv_exact(sock,13)
        if head[:5]!=b'ZBXD\x01': raise ValueError('Неожиданный заголовок Zabbix')
        length=struct.unpack('<Q',head[5:])[0]
        if length>1024*1024: raise ValueError('Слишком большой ответ')
        response=json.loads(recv_exact(sock,length))
    info=response.get('info','')
    match=re.search(r'processed:\s*(\d+);\s*failed:\s*(\d+);\s*total:\s*(\d+)',info)
    if (response.get('response')!='success' or not match or
        tuple(map(int,match.groups()))!=(len(records),0,len(records))):
        raise ValueError('Zabbix не принял все значения: '+str(response))
    return response

def append_log(path,event):
    # Ограничиваем локальный журнал и сохраняем предыдущую часть.
    if path.exists() and path.stat().st_size>5*1024*1024:
        path.replace(path.with_suffix('.jsonl.1'))
    with path.open('a') as stream: stream.write(json.dumps(event,ensure_ascii=False)+'\n')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--lab',required=True)
    parser.add_argument('--interval',type=float,default=2)
    parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
    if args.interval<.5: parser.error('Минимальный интервал 0.5 с')
    d=load(args.lab); name='opla-'+d['LAB_ID']
    runtime=R/'monitoring/runtime'/d['LAB_ID'];runtime.mkdir(parents=True,exist_ok=True)
    lock=(runtime/'collector.lock').open('w')
    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: sys.exit('Сборщик для этого стенда уже работает')
    previous=None
    pending=deque(maxlen=1000)
    while True:
        start=time.monotonic();clock=int(time.time())
        try:
            data=collect(d['VICTIM_IP'],args.lab)
            event={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'lab':d['LAB_ID'],'event':'snapshot','metrics':data}
            append_log(runtime/'events.jsonl',event)
            records=[{'host':name,'key':item_key(k),'value':str(data[k]),'clock':clock} for k in METRICS]
            records.append({'host':name,'key':'xdp.mode','value':data['mode'],'clock':clock})
            # Передаём агрегированные события интервала, а не каждый отброшенный пакет.
            event_keys=['loaded','mode','drop','map_full','fragment_drop',
                        'http_available','http_limited','http_5xx','http_parse_errors']
            if previous is None or any(data[k]!=previous[k] for k in event_keys):
                pending.append({'host':name,'key':'xdp.events','value':json.dumps(event),'clock':clock})
            send(records+list(pending)); pending.clear(); previous=data
        except (OSError,ValueError,subprocess.SubprocessError) as e:
            append_log(runtime/'events.jsonl',{'time':clock,'event':'collection_error','error':str(e)})
            print('Ошибка мониторинга: '+str(e),file=sys.stderr,flush=True)
            if args.once: return 1
        if args.once:return 0
        time.sleep(max(0,args.interval-(time.monotonic()-start)))
if __name__=='__main__':
    try: sys.exit(main())
    except KeyboardInterrupt: pass
