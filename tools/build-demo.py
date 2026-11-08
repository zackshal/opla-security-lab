#!/usr/bin/env python3
"""Render repository-native README media from saved observations; never run a lab."""
import argparse
import hashlib
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
FONTS = Path('/usr/share/fonts/truetype/dejavu')
BG, PANEL, LINE = '#090a10', '#11131d', '#303653'
PANEL_ALT, INK, MUTED = '#1a1d2a', '#f3f2ff', '#a7a5bc'
CYAN, GREEN, AMBER, RED = '#4ad9d0', '#10b83c', '#ff5a0a', '#ff1825'
PURPLE = '#6d38ff'
W, H = 1080, 660


def font(size, mono=False, bold=False):
    name = 'DejaVuSansMono' if mono else 'DejaVuSans'
    return ImageFont.truetype(str(FONTS / (name + ('-Bold' if bold else '') + '.ttf')), size)


def text(draw, xy, value, size=20, fill=INK, mono=False, bold=False):
    draw.text(xy, value, font=font(size, mono, bold), fill=fill)


def box(draw, bounds, fill=PANEL, outline=LINE, radius=15):
    draw.rounded_rectangle(bounds, radius=radius, fill=fill, outline=outline, width=1)


def canvas(index, title, subtitle):
    img = Image.new('RGB', (W, H), BG)
    d = ImageDraw.Draw(img)
    for x in range(0, W, 32):
        d.line((x, 0, x, H), fill='#0d1b2d')
    for y in range(0, H, 32):
        d.line((0, y, W, y), fill='#0d1b2d')
    d.rectangle((0, 0, W, 6), fill=CYAN)
    text(d, (38, 25), 'OPLA // SECURITY LAB', 15, CYAN, mono=True, bold=True)
    text(d, (855, 25), 'OFFLINE / ARCHIVE', 15, MUTED, mono=True)
    text(d, (38, 65), title, 33, INK, bold=True)
    text(d, (38, 112), subtitle, 17, MUTED)
    d.line((38, 595, 1042, 595), fill=LINE)
    text(d, (38, 615), 'ARCHIVE / OPERATOR OUTPUT / 24.10.2026 / ARCHIVED OUTPUT', 15, MUTED, mono=True)
    for i in range(4):
        d.rounded_rectangle((918+i*32, 620, 938+i*32, 625), radius=2,
                            fill=CYAN if index == i else LINE)
    return img


def metric(d, x, label, value, color):
    box(d, (x, 166, x+310, 284))
    text(d, (x+20, 181), label, 15, MUTED)
    text(d, (x+20, 211), f'{value:,}', 39, color, bold=True)


def terminal(d, lines, visible, y=313):
    box(d, (38, y, 1042, 572), fill='#12213b')
    for x, c in ((58, RED), (77, AMBER), (96, GREEN)):
        d.ellipse((x, y+17, x+8, y+25), fill=c)
    text(d, (125, y+13), 'сохранённый вывод / выбранные строки', 14, '#b9c9e1')
    for i, line in enumerate(lines[:visible]):
        text(d, (60, y+55+i*32), line, 19,
             CYAN if line.startswith('$') else INK, mono=True)


def draw_scene(scene, step, data):
    syn, http = data['syn_scenario'], data['http_burst']
    if scene == 0:
        img = canvas(0, 'Три роли. Две сети. Один опыт.', 'Схема текущей архитектуры / роли и границы наблюдения')
        d = ImageDraw.Draw(img)
        for x, title, note in ((38, 'ATTACKER', 'Конечная тестовая нагрузка'),
                                (382, 'VICTIM', 'XDP / nginx / Suricata'),
                                (726, 'CLIENT', 'Независимая HTTP-проверка')):
            box(d, (x, 174, x+316, 292))
            text(d, (x+22, 198), title, 23, CYAN, bold=True)
            text(d, (x+22, 239), note, 17, MUTED)
        for x in (196, 540, 884):
            d.line((x, 292, x, 338), fill=CYAN, width=3)
        box(d, (38, 338, 1042, 393), outline=CYAN)
        text(d, (305, 353), 'DATA NETWORK / изолированная /29', 19, CYAN, mono=True)
        box(d, (38, 425, 612, 558))
        text(d, (60, 448), 'Отдельная сеть управления', 22, bold=True)
        text(d, (60, 488), 'SSH → collector → Zabbix → отчёт', 20, GREEN, mono=True)
        box(d, (636, 425, 1042, 558))
        text(d, (660, 448), 'Вопросы эксперимента', 20, bold=True)
        text(d, (660, 488), 'Обнаружено? Отброшено? Доступно?', 18, MUTED)
    elif scene == 1:
        img = canvas(1, 'От пакета — к решению XDP', 'Архивный SYN-опыт / фоновые SYN учитываются / производительность не измерялась')
        d = ImageDraw.Draw(img)
        metric(d, 38, 'ПРИРОСТ SYN', syn['syn_after']-syn['syn_before'], CYAN)
        metric(d, 385, 'ПРОПУЩЕНО SYN', syn['pass_after']-syn['pass_before'], GREEN)
        metric(d, 732, 'ОТБРОШЕНО SYN', syn['drop_after']-syn['drop_before'], AMBER)
        terminal(d, ['$ bash bin/traffic-scenario.sh syn',
                     f"syn:   {syn['syn_before']:4} -> {syn['syn_after']:4}   delta={syn['syn_after']-syn['syn_before']}",
                     f"pass:  {syn['pass_before']:4} -> {syn['pass_after']:4}   delta={syn['pass_after']-syn['pass_before']}",
                     f"drop:  {syn['drop_before']:4} -> {syn['drop_after']:4}   delta={syn['drop_after']-syn['drop_before']}",
                     f"generator exit: {syn['generator_exit_code']} / XDP mode: {data['xdp']['mode']}"], step)
    elif scene == 2:
        img = canvas(2, 'HTTP: наблюдение на уровне приложения', 'Отдельный архивный HTTP burst / ограничение запросов nginx')
        d = ImageDraw.Draw(img)
        metric(d, 38, 'HTTP-ЗАПРОСОВ', http['requests'], CYAN)
        metric(d, 385, 'ОТВЕТОВ HTTP 200', http['http_200'], GREEN)
        metric(d, 732, 'ОТВЕТОВ HTTP 429', http['http_429'], AMBER)
        terminal(d, ['$ bash bin/security-http-test.sh',
                     f"HTTP 200: {http['http_200']} / HTTP 429: {http['http_429']}",
                     f"http_limited: {http['limited_before']} -> {http['limited_after']}",
                     f"5xx delta: {http['errors_5xx_delta']} / parse errors delta: {http['parse_errors_delta']}",
                     'Доступность client измеряется отдельно.'], step)
    else:
        img = canvas(3, 'Что подтверждено этим опытом', 'Наблюдения и пробелы в доказательствах фиксируются в одном отчёте')
        d = ImageDraw.Draw(img)
        rows = [('ЗАПИСАНО', 'Native XDP подключена; счётчик drop растёт', GREEN),
                ('ЗАПИСАНО', 'Есть HTTP 429 и прирост nginx limited', GREEN),
                ('НЕ ПОДТВЕРЖДЕНО', 'Непрерывная доступность client во время нагрузки', AMBER),
                ('НЕ ПОДТВЕРЖДЕНО', 'События Suricata в этой архивной записи', AMBER),
                ('СЛЕДУЮЩИЙ ШАГ', 'Чистый полный прогон текущей версии', CYAN)]
        for i, (label, desc, color) in enumerate(rows[:step]):
            y = 167+i*75
            box(d, (38, y, 1042, y+61))
            text(d, (56, y+19), label, 15, color, mono=True, bold=True)
            text(d, (244, y+18), desc, 19)
    return img


def banner(out):
    # Native SVG: static, self-contained and rendered by GitLab/GitHub without scripts.
    svg = '''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="320" viewBox="0 0 1280 320" role="img" aria-labelledby="title desc">
<title id="title">OPLA — лаборатория безопасности Linux</title><desc id="desc">Три виртуальные машины, две изолированные сети, наблюдаемые результаты экспериментов.</desc>
<defs><pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#161a29" stroke-width="1"/></pattern><linearGradient id="glow" x1="0" x2="1"><stop stop-color="#4ad9d0" stop-opacity=".24"/><stop offset="1" stop-color="#6d38ff" stop-opacity=".03"/></linearGradient></defs>
<rect width="1280" height="320" rx="20" fill="#090a10"/><rect width="1280" height="320" rx="20" fill="url(#grid)"/><rect width="1280" height="7" rx="3" fill="#4ad9d0"/>
<rect x="40" y="44" width="700" height="232" rx="16" fill="url(#glow)" stroke="#303653"/>
<text x="70" y="78" font-family="monospace" font-size="15" letter-spacing="2" fill="#4ad9d0">OPLA // SECURITY LAB</text>
<text x="70" y="158" font-family="sans-serif" font-size="76" font-weight="700" fill="#f3f2ff">OPLA</text>
<text x="74" y="202" font-family="sans-serif" font-size="25" fill="#a7a5bc">Наблюдать. Защищать. Объяснять.</text>
<text x="74" y="244" font-family="monospace" font-size="17" fill="#6d38ff">eBPF/XDP · Suricata · nginx · Zabbix</text>
<g font-family="monospace"><rect x="782" y="44" width="208" height="102" rx="14" fill="#11131d" stroke="#303653"/><rect x="1010" y="44" width="226" height="102" rx="14" fill="#11131d" stroke="#303653"/><rect x="782" y="166" width="454" height="110" rx="14" fill="#11131d" stroke="#303653"/>
<text x="810" y="83" font-size="30" font-weight="700" fill="#10b83c">3 VM</text><text x="810" y="117" font-size="14" fill="#a7a5bc">attacker / victim / client</text>
<text x="1038" y="83" font-size="30" font-weight="700" fill="#ff5a0a">2 NET</text><text x="1038" y="117" font-size="14" fill="#a7a5bc">data + management</text>
<text x="810" y="207" font-size="17" font-weight="700" fill="#f3f2ff">packet → decision → evidence</text><text x="810" y="240" font-size="14" fill="#a7a5bc">bounded load / reproducible report</text></g>
</svg>'''
    (out / 'banner.svg').write_text(svg+'\n')


def results_card(out, data):
    img = canvas(1, 'Сначала данные. Затем выводы.', 'Вывод оператора от 24.10.2026 / непрерывный client probe не приложен')
    d = ImageDraw.Draw(img)
    syn, h = data['syn_scenario'], data['http_burst']
    values = [syn['pass_after']-syn['pass_before'], syn['drop_after']-syn['drop_before']]
    groups = [(172, 'SYN: прирост накопительных счётчиков', values, ['PASS', 'DROP'], [GREEN, AMBER]),
              (358, 'HTTP: ответы в отдельном burst-опыте', [h['http_200'], h['http_429']], ['200', '429'], [GREEN, AMBER])]
    for y, heading, vals, labels, colors in groups:
        text(d, (38, y), heading, 23, bold=True)
        total = sum(vals)
        for i, (value, label, color) in enumerate(zip(vals, labels, colors)):
            yy=y+49+i*54
            text(d, (38, yy), label, 17, MUTED, mono=True)
            d.rounded_rectangle((130, yy, 880, yy+27), radius=5, fill=PANEL)
            d.rounded_rectangle((130, yy, 130+max(8,750*value/total), yy+27), radius=5, fill=color)
            text(d, (911, yy-1), f'{value:,}', 21, color, mono=True)
    text(d, (38, 553), 'Счётчики подтверждают обработку; непрерывная доступность требует отдельной проверки.', 16, MUTED)
    img.save(out/'results.png', optimize=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'assets/demo')
    args = parser.parse_args()
    out=args.output;out.mkdir(parents=True,exist_ok=True)
    source=ROOT/'assets/demo/observed-results.json'
    data=json.loads(source.read_text())
    banner(out)
    results_card(out,data)
    frames=[];durations=[]
    for scene in range(4):
        for step in range(1,6):
            frames.append(draw_scene(scene,step,data))
            durations.append(240 if step<5 else 2600)
    frames[0].save(out/'overview.gif',save_all=True,append_images=frames[1:],
                   duration=durations,loop=0,optimize=True,disposal=2)
    frames[9].save(out/'overview-poster.png',optimize=True)
    syn=data['syn_scenario'];h=data['http_burst']
    (out/'results.txt').write_text(
        'OPLA / архивные наблюдения / 24.10.2026\n'
        'Источник: терминальный вывод пользователя; независимо не повторялся.\n\n'
        f"Прирост SYN counters: syn +{syn['syn_after']-syn['syn_before']}, "
        f"pass +{syn['pass_after']-syn['pass_before']}, drop +{syn['drop_after']-syn['drop_before']}\n"
        f"Отдельный HTTP burst: {h['requests']} запросов; HTTP 200={h['http_200']}; HTTP 429={h['http_429']}\n"
        'Наблюдения не подтверждают полное предотвращение, непрерывную доступность client,\n'
        'готовность Suricata или чистое развёртывание текущей версии.\n')
    # The SVG cards are dependency-free and are kept alongside the optional
    # Pillow-rendered старый GIF/PNG artifacts.
    names=['banner.svg','overview.svg','results.svg','results.png','results.txt',
           'overview.gif','overview-poster.png']
    manifest={'renderer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'source':'observed-results.json','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
              'provenance':data['provenance'],'animation_timing':'illustrative; not execution time',
              'live_execution_performed':False,
              'artifacts':{name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in names}}
    (out/'media-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Rendered banner, GIF, static result card, text summary and provenance manifest.')


if __name__=='__main__':
    main()
