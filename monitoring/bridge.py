#!/usr/bin/env python3
"""SSH-снимок -> журнал JSONL -> Zabbix trapper. Запускается на хосте."""
import argparse
import datetime
import fcntl
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'bin'))
from state import load, ssh_ip
from catalog import METRICS, item_key
from opla_process import run_bounded

MAX_PENDING_EVENTS = 1000
MAX_PENDING_BYTES = 1024 * 1024

def collect(ip,lab):
    management_ip = ssh_ip(lab, ip)
    cmd=['ssh','-i',os.environ.get('SSH_KEY',str(Path.home()/'.ssh/id_ed25519')),
         '-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=yes',
         '-o',f'UserKnownHostsFile={lab}/known_hosts',f'student@{management_ip}',
         'sudo python3 /tmp/xdp-build/collect.py']
    result=run_bounded(cmd,timeout=10,max_output_bytes=128*1024)
    if getattr(result,'output_limited',False):
        raise ValueError('Guest collector output exceeds 128 KiB limit')
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode,cmd,output=result.stdout,stderr=result.stderr)
    data=json.loads(result.stdout)
    if not isinstance(data, dict):
        raise ValueError('Guest collector snapshot must be a JSON object')
    if any(type(data.get(k)) is not int or data[k]<0 for k in METRICS):
        raise ValueError('Некорректный снимок метрик')
    if not isinstance(data.get('scan_details'), str):
        raise ValueError('Port-scan details must be a string; deploy the new collector')
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
    if not isinstance(response, dict):
        raise ValueError('Некорректный ответ Zabbix: ожидался JSON-объект')
    info=response.get('info','')
    if not isinstance(info,str):
        raise ValueError('Некорректный ответ Zabbix: поле info должно быть строкой')
    match=re.search(r'processed:\s*(\d+);\s*failed:\s*(\d+);\s*total:\s*(\d+)',info)
    if (response.get('response')!='success' or not match or
        tuple(map(int,match.groups()))!=(len(records),0,len(records))):
        raise ValueError('Zabbix не принял все значения: '+str(response))
    return response

def load_pending(path):
    """Read the per-lab event outbox without following links or accepting damage."""
    try:
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
    except FileNotFoundError:
        return []
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_PENDING_BYTES:
            raise ValueError('pending event outbox is not a bounded single-link file')
        raw=b''
        while len(raw) <= MAX_PENDING_BYTES:
            chunk=os.read(fd,min(65536,MAX_PENDING_BYTES+1-len(raw)))
            if not chunk:
                break
            raw+=chunk
        if len(raw)>MAX_PENDING_BYTES:
            raise ValueError('pending event outbox exceeds size limit')
    finally:
        os.close(fd)
    try:
        records=json.loads(raw or b'[]')
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('pending event outbox is malformed') from exc
    if (not isinstance(records,list) or len(records)>MAX_PENDING_EVENTS
            or any(not isinstance(record,dict)
                   or set(record)!={'host','key','value','clock'}
                   or not all(isinstance(record[key],str) for key in ('host','key','value'))
                   or type(record['clock']) is not int or record['clock']<0
                   for record in records)):
        raise ValueError('pending event outbox has invalid records')
    return records

def save_pending(path, records):
    """Atomically persist the bounded at-least-once Zabbix event outbox."""
    if len(records)>MAX_PENDING_EVENTS:
        raise ValueError('pending event count exceeds limit; refusing to drop events')
    payload=(json.dumps(records,separators=(',',':'))+'\n').encode()
    if len(payload)>MAX_PENDING_BYTES:
        raise ValueError('pending event outbox exceeds size limit; refusing to drop events')
    path=Path(path)
    fd,name=tempfile.mkstemp(prefix='.pending-',dir=path.parent)
    temporary=Path(name)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,path)
        directory_fd=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise

def last_pending_snapshot(records):
    """Recover comparison state so an unchanged retry does not mint a duplicate event."""
    for record in reversed(records):
        if record['key'] != 'xdp.events':
            continue
        try:
            event=json.loads(record['value'])
        except (TypeError,json.JSONDecodeError):
            return None
        metrics=event.get('metrics') if isinstance(event,dict) else None
        return metrics if isinstance(metrics,dict) else None
    return None

def prepare_runtime(lab_id):
    """Create/check per-lab runtime directories without following path links."""
    # The installed program tree (normally /opt/opla) is root-owned and must
    # stay immutable. Collector state belongs to the invoking user instead.
    local=Path.home()/'.local'
    state=local/'state'
    opla_state=state/'opla'
    monitoring=opla_state/'monitoring'
    root=monitoring/'runtime'
    for path in (local, state, opla_state, monitoring, root, root/lab_id):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info=path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022):
            raise ValueError(f'unsafe monitoring runtime directory: {path}')
    return root/lab_id

def acquire_collector_lock(runtime):
    """Return a held, no-follow per-lab lock descriptor."""
    lock_path=Path(runtime)/'collector.lock'
    fd=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise ValueError('collector lock must be a single-link regular file')
    os.fchmod(fd,0o600)
    lock=os.fdopen(fd,'r+')
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BaseException:
        lock.close()
        raise
    return lock

def append_log(path,event):
    # Ограничиваем локальный журнал и сохраняем предыдущую часть.
    try:
        info=path.lstat()
    except FileNotFoundError:
        info=None
    if info is not None:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('monitoring event log must be a single-link regular file')
        if info.st_size>5*1024*1024:
            path.replace(path.with_suffix('.jsonl.1'))
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('monitoring event log must be a single-link regular file')
        os.fchmod(fd,0o600)
        payload=memoryview((json.dumps(event,ensure_ascii=False)+'\n').encode())
        while payload:
            written=os.write(fd,payload)
            if written<=0:
                raise OSError('short write to monitoring event log')
            payload=payload[written:]
        os.fsync(fd)
    finally:
        os.close(fd)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--lab',required=True)
    parser.add_argument('--interval',type=float,default=2)
    parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
    if not math.isfinite(args.interval) or args.interval<.5:
        parser.error('Интервал должен быть конечным и не менее 0.5 с')
    try:
        return run_collector(args)
    except (OSError,ValueError) as exc:
        print(f'BLOCKED: {exc}',file=sys.stderr)
        return 2

def run_collector(args):
    d=load(args.lab); name='opla-'+d['LAB_ID']
    runtime=prepare_runtime(d['LAB_ID'])
    try:
        lock=acquire_collector_lock(runtime)
    except BlockingIOError:
        print('Сборщик для этого стенда уже работает',file=sys.stderr)
        return 1
    with lock:
        outbox=runtime/'pending-events.json'
        pending=load_pending(outbox)
        previous=last_pending_snapshot(pending)
        while True:
            start=time.monotonic();clock=int(time.time())
            try:
                data=collect(d['VICTIM_IP'],args.lab)
                event={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       'lab':d['LAB_ID'],'event':'snapshot','metrics':data}
                append_log(runtime/'events.jsonl',event)
                records=[{'host':name,'key':item_key(k),'value':str(data[k]),'clock':clock} for k in METRICS]
                records.append({'host':name,'key':'xdp.mode','value':data['mode'],'clock':clock})
                records.append({'host':name,'key':'scan.details','value':data['scan_details'],'clock':clock})
                # Передаём агрегированные события интервала, а не каждый отброшенный пакет.
                event_keys=['loaded','mode','drop','map_full','fragment_drop','xdp_scan_mode','xdp_scan_events','xdp_scan_drop',
                            'http_available','http_limited','http_5xx','http_parse_errors',
                            'ids_enabled','ids_up','ids_alerts','ids_blocked','ids_parse_errors',
                            'scan_enabled','scan_up','scan_active','scan_alerts','scan_capture_drops','scan_evictions']
                if previous is None or any(data[k]!=previous[k] for k in event_keys):
                    pending.append({'host':name,'key':'xdp.events','value':json.dumps(event),'clock':clock})
                save_pending(outbox,pending)
                # The transition is now durable. A failed send retries it as-is
                # instead of minting another event from the same snapshot.
                previous=data
                send(records+pending)
                pending=[]
                save_pending(outbox,pending)
            except (OSError,ValueError,subprocess.SubprocessError) as e:
                append_log(runtime/'events.jsonl',{'time':clock,'event':'collection_error','error':str(e)})
                print('Ошибка мониторинга: '+str(e),file=sys.stderr,flush=True)
                if args.once: return 1
            if args.once:return 0
            time.sleep(max(0,args.interval-(time.monotonic()-start)))
if __name__=='__main__':
    try: sys.exit(main())
    except KeyboardInterrupt: pass
