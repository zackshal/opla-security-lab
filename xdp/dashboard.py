#!/usr/bin/env python3
"""Живые счётчики и скорости. Нажмите q, чтобы выйти."""
import curses
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'monitoring'))
from bridge import collect

def draw(screen,ip,lab):
    screen.timeout(1000)
    previous=None
    while True:
        now=time.monotonic()
        lines=['XDP / victim '+ip+'     q: выход']
        try:
            data=collect(ip,lab)
            lines.append('Режим: '+data['mode'])
            for key in ['syn','pass','drop','map_full','fragment_drop']:
                rate=0
                if previous and data[key]>=previous[1][key]:
                    rate=(data[key]-previous[1][key])/(now-previous[0])
                lines.append(f'{key:16s} {data[key]:12d}   {rate:10.1f}/s')
            lines.append('Скорости рассчитаны по фактическому времени между снимками.')
            previous=(now,data)
        except (OSError,ValueError,subprocess.SubprocessError) as e:
            lines.append('Ошибка сбора: '+str(e));previous=None
        screen.erase();height,width=screen.getmaxyx()
        for y,line in enumerate(lines[:max(0,height-1)]):
            if width>1: screen.addnstr(y,0,line,width-1)
        screen.refresh()
        if screen.getch() in [ord('q'),ord('Q'),27]: return
if __name__=='__main__':
    try: curses.wrapper(draw,sys.argv[1],os.environ['LAB_DIR'])
    except KeyboardInterrupt: pass
