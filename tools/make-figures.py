#!/usr/bin/env python3
"""Векторные схемы и временные PNG для печатного комплекта."""
from pathlib import Path
import html
import math
from PIL import Image, ImageDraw, ImageFont

R = Path(__file__).resolve().parents[1]
FONT = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'


def draw(name, size, nodes, edges, notes):
    image = Image.new('RGB', size, 'white')
    pen = ImageDraw.Draw(image)
    font = ImageFont.truetype(FONT, 23)
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{size[0]}" height="{size[1]}" viewBox="0 0 {size[0]} {size[1]}">', '<rect width="100%" height="100%" fill="white"/>']
    for x1,y1,x2,y2 in edges:
        angle = math.atan2(y2-y1,x2-x1)
        arrow = [(x2,y2),(x2-15*math.cos(angle-.45),y2-15*math.sin(angle-.45)),(x2-15*math.cos(angle+.45),y2-15*math.sin(angle+.45))]
        pen.line((x1,y1,x2,y2), fill='#334155', width=3)
        pen.polygon(arrow, fill='#334155')
        svg.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#334155" stroke-width="3"/>')
        svg.append('<polygon points="'+' '.join(f'{x:.1f},{y:.1f}' for x,y in arrow)+'" fill="#334155"/>')
    for x,y,w,h,lines in nodes:
        pen.rounded_rectangle((x,y,x+w,y+h),radius=10, fill='#eef4fa',outline='#334155',width=2)
        svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="#eef4fa" stroke="#334155" stroke-width="2"/>')
        for i,line in enumerate(lines):
            cy=y+h/2+(i-(len(lines)-1)/2)*31
            pen.text((x+w/2,cy),line,font=font,fill='#172b45',anchor='mm')
            svg.append(f'<text x="{x+w/2}" y="{cy+8}" text-anchor="middle" font-family="DejaVu Sans,sans-serif" font-size="23" fill="#172b45">{html.escape(line)}</text>')
    for x,y,line in notes:
        pen.text((x,y),line,font=font,fill='#334155')
        svg.append(f'<text x="{x}" y="{y+23}" font-family="DejaVu Sans,sans-serif" font-size="23" fill="#334155">{html.escape(line)}</text>')
    svg.append('</svg>')
    target=R/'docs/figures';target.mkdir(parents=True,exist_ok=True)
    (target/(name+'.svg')).write_text('\n'.join(svg)+'\n')
    assets=R/'release-artifacts/.figures';assets.mkdir(parents=True,exist_ok=True)
    image.save(assets/(name+'.png'))


def main():
    draw('topology',(1400,790),[
        (40,30,360,110,['attacker','hping3 / nmap / tcpdump']),
        (520,30,360,110,['victim','XDP / nginx / Suricata']),
        (1000,30,360,110,['client','Независимый HTTP']),
        (40,245,600,110,['Data bridge / ens3','Изолированная /29 для нагрузки']),
        (760,245,600,110,['Management bridge / ens4','Другая /29 для SSH']),
        (40,550,570,130,['Хост / QEMU-KVM / nftables','SSH collector по management']),
        (780,550,580,130,['Zabbix / PostgreSQL','localhost:8080 / 10051'])],
        [(160,140,160,245),(600,140,430,245),(1080,140,580,245),
         (350,140,850,245),(800,140,1050,245),(1280,140,1250,245),
         (1060,355,440,550),(610,615,780,615)],
        [(45,405,'Адреса назначает allocator; две отдельные /29.'),
         (45,445,'Forwarding вне bridge запрещён; управление не идёт через XDP.'),
         (45,745,'Нагрузка разрешена только между VM своего lab.')])
    draw('packet-path',(1400,800),[
        (40,40,360,100,['Ethernet / до 2 VLAN','Проверка доступной длины']),
        (520,40,360,100,['IPv4 / IHL / total','TCP-фрагменты: DROP']),
        (1000,40,360,100,['TCP / doff / длина','Безопасные обращения']),
        (520,250,360,100,['SYN=1, ACK=0?','Прочий трафик: PASS']),
        (440,450,520,120,['Окно source IP + spin lock','count++; порог THRESHOLD']),
        (40,660,360,100,['count ≤ THRESHOLD','PASS + счётчик']),
        (1000,660,360,100,['count > THRESHOLD','DROP + счётчик'])],
        [(400,90,520,90),(880,90,1000,90),(1180,140,780,250),(700,350,700,450),(440,550,220,660),(960,550,1180,660)],
        [(60,220,'Проверки до учёта SYN'),(60,260,'Ошибка длины: DROP'),(60,385,'Всё ограничение - для IPv4 SYN'),(990,385,'Hash-map: до 4096 IP'),(500,620,'Scan policy + per-CPU счётчики')])


if __name__=='__main__':
    main()
