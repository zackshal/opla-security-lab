#!/usr/bin/env python3
"""Render a clearly labelled replay of supplied terminal output, not a live capture."""
import json
import subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'assets' / 'demo'
OUT.mkdir(parents=True, exist_ok=True)
FONT = Path('/usr/share/fonts/truetype/dejavu')
mono = ImageFont.truetype(str(FONT/'DejaVuSansMono.ttf'), 22)
small = ImageFont.truetype(str(FONT/'DejaVuSans.ttf'), 18)
title = ImageFont.truetype(str(FONT/'DejaVuSans-Bold.ttf'), 31)
scenes = [
    ('01 / Native XDP', [
        '$ make xdp-all THRESHOLD=100',
        'clang ... -target bpf ...',
        'XDP: native',
        '$ sudo bpftool net show   # inside victim',
        'xdp:',
        'ens3(2) driver id 52',
        '',
        'Program: xdp_ddos_protect | JIT: enabled',
    ]),
    ('02 / Automatic Zabbix provisioning', [
        '$ bash bin/observability-up.sh',
        'nginx: configuration file test is successful',
        'HTTP policy: apply',
        '',
        '28 items | 12 triggers | dashboard: 3 pages',
        'opla-monitor-lab-kSV4ZZai.service started',
        '',
        'XDP and events / HTTP protection / Interface traffic',
    ]),
    ('03 / SYN experiment', [
        '$ bash bin/traffic-scenario.sh syn',
        'syn:   35 -> 2038   delta=2003',
        'pass:  35 ->  335   delta=300',
        'drop:   0 -> 1703   delta=1703',
        'map_full: 0 -> 0',
        'fragment_drop: 0 -> 0',
        '',
        'reports/scenario-syn-HNU2AKnM | generator exit: 0',
    ]),
    ('04 / HTTP burst: nginx rejects excess requests', [
        '$ bash bin/security-http-test.sh',
        'requests: 200',
        'HTTP 200: 11',
        'HTTP 429: 189',
        '',
        'http_requests: 32 -> 233   delta=201',
        'http_limited:   0 -> 189   delta=189',
        'http_5xx: 0 -> 0 | http_parse_errors: 0 -> 0',
    ]),
    ('05 / Result and scope', [
        '$ make xdp-stats',
        'loaded=1 | mode=native | drop=3403',
        'http_available=1 | http_status=200',
        'http_limited=189 | http_parse_errors=0',
        '',
        'Observed functional result, not a throughput benchmark.',
        'Suricata: optional rules only; no deployed IDS claimed.',
        'Full dashboard screenshots require a real screen capture.',
    ]),
]
frames=[]
for i,(heading,lines) in enumerate(scenes):
    img=Image.new('RGB',(1280,720),'#0c1423')
    d=ImageDraw.Draw(img)
    d.rounded_rectangle((24,24,1256,696),radius=20,fill='#132139',outline='#32496d',width=2)
    d.text((52,44),'OPLA / eBPF-XDP Security Lab',font=title,fill='#eff5ff')
    d.text((52,91),'REPLAY OF SAVED OUTPUT · NOT A LIVE SCREEN RECORDING',font=small,fill='#ffd37f')
    d.text((52,137),heading,font=title,fill='#80dbce')
    for n,line in enumerate(lines):
        d.text((52,208+n*43),line,font=mono,fill='#82e1ac' if line.startswith('$') else '#e4edf9')
    d.line((52,610,1228,610),fill='#32496d',width=2)
    d.text((52,631),'Source: user terminal transcript · 24 Oct 2026 · lab-kSV4ZZai',font=small,fill='#b8c9df')
    d.text((52,660),'Frame timing is editorial; it does not represent execution time.',font=small,fill='#b8c9df')
    frames.append(img)
    img.save(OUT/f'replay-{i+1:02d}.png')
frames[0].save(OUT/'terminal-replay.gif',save_all=True,append_images=frames[1:],duration=[4500]*5,loop=0,optimize=True)
frames[3].save(OUT/'terminal-replay-poster.png')
subprocess.run(['ffmpeg','-hide_banner','-loglevel','error','-y','-i',str(OUT/'terminal-replay.gif'),
                '-an','-vf','fps=15','-c:v','libx264','-crf','23','-pix_fmt','yuv420p',
                '-movflags','+faststart',str(OUT/'terminal-replay.mp4')],check=True)
for i in range(5):
    (OUT/f'replay-{i+1:02d}.png').unlink()
print('Rendered 5 labelled replay scenes, GIF and MP4.')
