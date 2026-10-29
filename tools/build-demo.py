#!/usr/bin/env python3
"""Render repository-native README media from saved observations; never run a lab."""
import argparse
import hashlib
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
FONTS = Path('/usr/share/fonts/truetype/dejavu')
BG, PANEL, LINE = '#0b1020', '#141d31', '#2a3651'
WHITE, MUTED = '#ecf2ff', '#a4b3ca'
CYAN, GREEN, AMBER, RED = '#66def0', '#78e3b1', '#ffd18a', '#ff8b9a'
W, H = 1080, 660


def font(size, mono=False, bold=False):
    name = 'DejaVuSansMono' if mono else 'DejaVuSans'
    return ImageFont.truetype(str(FONTS / (name + ('-Bold' if bold else '') + '.ttf')), size)


def text(draw, xy, value, size=20, fill=WHITE, mono=False, bold=False):
    draw.text(xy, value, font=font(size, mono, bold), fill=fill)


def box(draw, bounds, fill=PANEL, outline=LINE, radius=15):
    draw.rounded_rectangle(bounds, radius=radius, fill=fill, outline=outline, width=1)


def canvas(index, title, subtitle):
    img = Image.new('RGB', (W, H), BG)
    d = ImageDraw.Draw(img)
    text(d, (38, 25), 'OPLA / SECURITY LAB', 15, CYAN, bold=True)
    text(d, (828, 25), 'OBSERVE / EXPLAIN', 15, MUTED)
    text(d, (38, 65), title, 33, bold=True)
    text(d, (38, 112), subtitle, 17, MUTED)
    d.line((38, 595, 1042, 595), fill=LINE)
    text(d, (38, 615), 'REPLAY  /  saved user observations, 24 Oct 2026  /  not a live capture', 15, MUTED)
    for i in range(4):
        d.rounded_rectangle((918+i*32, 620, 938+i*32, 625), radius=2,
                            fill=CYAN if index == i else LINE)
    return img


def metric(d, x, label, value, color):
    box(d, (x, 166, x+310, 284))
    text(d, (x+20, 181), label, 15, MUTED)
    text(d, (x+20, 211), f'{value:,}', 39, color, bold=True)


def terminal(d, lines, visible, y=313):
    box(d, (38, y, 1042, 572), fill='#0e1627')
    for x, c in ((58, RED), (77, AMBER), (96, GREEN)):
        d.ellipse((x, y+17, x+8, y+25), fill=c)
    text(d, (125, y+13), 'recorded output / selected lines', 14, MUTED)
    for i, line in enumerate(lines[:visible]):
        text(d, (60, y+55+i*32), line, 19,
             CYAN if line.startswith('$') else WHITE, mono=True)


def draw_scene(scene, step, data):
    syn, http = data['syn_scenario'], data['http_burst']
    if scene == 0:
        img = canvas(0, 'One lab. Three perspectives.', 'Architecture diagram / conceptual view of the current built-in topology')
        d = ImageDraw.Draw(img)
        for x, title, note in ((38, 'ATTACKER', 'bounded test traffic'),
                                (382, 'VICTIM', 'XDP / nginx / Suricata'),
                                (726, 'CLIENT', 'independent HTTP')):
            box(d, (x, 174, x+316, 292))
            text(d, (x+22, 198), title, 23, CYAN, bold=True)
            text(d, (x+22, 239), note, 17, MUTED)
        for x in (196, 540, 884):
            d.line((x, 292, x, 338), fill=CYAN, width=3)
        box(d, (38, 338, 1042, 393), outline=CYAN)
        text(d, (258, 353), 'ISOLATED DATA NETWORK  /  generated /29', 19, CYAN, mono=True)
        box(d, (38, 425, 612, 558))
        text(d, (60, 448), 'Separate management network', 22, bold=True)
        text(d, (60, 488), 'SSH collector -> Zabbix -> report', 20, GREEN, mono=True)
        box(d, (636, 425, 1042, 558))
        text(d, (660, 448), 'What the evidence answers', 20, bold=True)
        text(d, (660, 488), 'Detected? Dropped? Available?', 18, MUTED)
    elif scene == 1:
        img = canvas(1, 'SYN traffic: follow the counters.', 'Historical experiment / counters include background SYN / no throughput benchmark')
        d = ImageDraw.Draw(img)
        metric(d, 38, 'OBSERVED SYN DELTA', syn['syn_after']-syn['syn_before'], CYAN)
        metric(d, 385, 'PASSED SYN DELTA', syn['pass_after']-syn['pass_before'], GREEN)
        metric(d, 732, 'DROPPED SYN DELTA', syn['drop_after']-syn['drop_before'], AMBER)
        terminal(d, ['$ bash bin/traffic-scenario.sh syn',
                     f"syn:   {syn['syn_before']:4} -> {syn['syn_after']:4}   delta={syn['syn_after']-syn['syn_before']}",
                     f"pass:  {syn['pass_before']:4} -> {syn['pass_after']:4}   delta={syn['pass_after']-syn['pass_before']}",
                     f"drop:  {syn['drop_before']:4} -> {syn['drop_after']:4}   delta={syn['drop_after']-syn['drop_before']}",
                     f"generator exit: {syn['generator_exit_code']} / XDP mode: {data['xdp']['mode']}"], step)
    elif scene == 2:
        img = canvas(2, 'HTTP requests: a different layer.', 'Separate historical HTTP burst / nginx rate limiting / not a SYN result')
        d = ImageDraw.Draw(img)
        metric(d, 38, 'REQUESTS IN THE BURST', http['requests'], CYAN)
        metric(d, 385, 'HTTP 200 RESPONSES', http['http_200'], GREEN)
        metric(d, 732, 'HTTP 429 RESPONSES', http['http_429'], AMBER)
        terminal(d, ['$ bash bin/security-http-test.sh',
                     f"HTTP 200: {http['http_200']} / HTTP 429: {http['http_429']}",
                     f"http_limited: {http['limited_before']} -> {http['limited_after']}",
                     f"5xx delta: {http['errors_5xx_delta']} / parse errors delta: {http['parse_errors_delta']}",
                     'Client availability needs its own measurements.'], step)
    else:
        img = canvas(3, 'Show the result. Keep the limits.', 'Observed evidence and missing evidence belong in the same report')
        d = ImageDraw.Draw(img)
        rows = [('OBSERVED', 'Native XDP attachment and rising drop counters', GREEN),
                ('OBSERVED', 'HTTP 429 and rising nginx limited counter', GREEN),
                ('NOT SHOWN', 'Independent client coverage throughout each burst', AMBER),
                ('NOT SHOWN', 'Suricata evidence in this historical recording', AMBER),
                ('NEXT GATE', 'A clean full run of the current release', CYAN)]
        for i, (label, desc, color) in enumerate(rows[:step]):
            y = 167+i*75
            box(d, (38, y, 1042, y+61))
            text(d, (56, y+19), label, 15, color, mono=True, bold=True)
            text(d, (220, y+18), desc, 19)
    return img


def banner(out):
    # Native SVG: static, self-contained and rendered by GitLab/GitHub without scripts.
    svg = '''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="340" viewBox="0 0 1280 340" role="img" aria-labelledby="title desc">
<title id="title">OPLA Security Lab</title><desc id="desc">An isolated Linux security lab: observe traffic, explain defenses, preserve evidence.</desc>
<defs><linearGradient id="g"><stop stop-color="#0b1020"/><stop offset="1" stop-color="#192942"/></linearGradient></defs>
<rect width="1280" height="340" rx="22" fill="url(#g)"/>
<g fill="none" stroke="#304764" stroke-width="1"><path d="M780 0V340M860 0V340M940 0V340M1020 0V340M1100 0V340M1180 0V340M740 60H1280M740 140H1280M740 220H1280M740 300H1280"/></g>
<text x="52" y="65" font-family="sans-serif" font-size="17" letter-spacing="4" fill="#66def0">OBSERVE / DEFEND / EXPLAIN</text>
<text x="48" y="148" font-family="sans-serif" font-weight="700" font-size="72" fill="#ecf2ff">OPLA</text>
<text x="52" y="197" font-family="sans-serif" font-size="28" fill="#ecf2ff">Security Lab</text>
<text x="52" y="246" font-family="sans-serif" font-size="19" fill="#a4b3ca">Linux · eBPF/XDP · Suricata · Zabbix</text>
<text x="52" y="294" font-family="sans-serif" font-size="16" fill="#78e3b1">3 VM roles   /   2 isolated networks   /   evidence you can inspect</text>
<g stroke="#66def0" stroke-width="3" fill="none"><path d="M814 119H914V221H1014V119H1114"/><path d="M814 221H914" stroke="#78e3b1"/></g>
<g fill="#141d31" stroke="#66def0" stroke-width="2"><rect x="780" y="82" width="76" height="76" rx="16"/><rect x="878" y="184" width="76" height="76" rx="16"/><rect x="976" y="82" width="76" height="76" rx="16"/><rect x="1074" y="184" width="76" height="76" rx="16"/></g>
<g font-family="monospace" font-size="21" fill="#ecf2ff" text-anchor="middle"><text x="818" y="128">SYN</text><text x="916" y="230">XDP</text><text x="1014" y="128">IDS</text><text x="1112" y="230">OBS</text></g></svg>'''
    (out / 'banner.svg').write_text(svg+'\n')


def results_card(out, data):
    img = canvas(1, 'Two experiments. Inspectable results.', 'Historical user transcript / 24 Oct 2026 / independent client coverage not supplied')
    d = ImageDraw.Draw(img)
    syn, h = data['syn_scenario'], data['http_burst']
    values = [syn['pass_after']-syn['pass_before'], syn['drop_after']-syn['drop_before']]
    groups = [(172, 'SYN counter deltas', values, ['PASS', 'DROP'], [GREEN, AMBER]),
              (358, 'HTTP responses / separate burst', [h['http_200'], h['http_429']], ['200', '429'], [GREEN, AMBER])]
    for y, heading, vals, labels, colors in groups:
        text(d, (38, y), heading, 23, bold=True)
        total = sum(vals)
        for i, (value, label, color) in enumerate(zip(vals, labels, colors)):
            yy=y+49+i*54
            text(d, (38, yy), label, 17, MUTED, mono=True)
            d.rounded_rectangle((130, yy, 880, yy+27), radius=5, fill=PANEL)
            d.rounded_rectangle((130, yy, 130+max(8,750*value/total), yy+27), radius=5, fill=color)
            text(d, (911, yy-1), f'{value:,}', 21, color, mono=True)
    text(d, (38, 553), 'Counters demonstrate processing; they do not prove complete prevention or service uptime.', 16, MUTED)
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
        'OPLA / historical observations / 2026-10-24\n'
        'Source: user terminal transcript; not independently rerun.\n\n'
        f"SYN counters: syn +{syn['syn_after']-syn['syn_before']}, "
        f"pass +{syn['pass_after']-syn['pass_before']}, drop +{syn['drop_after']-syn['drop_before']}\n"
        f"Separate HTTP burst: {h['requests']} requests; HTTP 200={h['http_200']}; HTTP 429={h['http_429']}\n"
        'These observations do not establish complete prevention, continuous client uptime,\n'
        'Suricata readiness, or clean deployment of the current release.\n')
    names=['banner.svg','results.png','results.txt','overview.gif','overview-poster.png']
    manifest={'renderer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'source':'observed-results.json','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
              'provenance':data['provenance'],'animation_timing':'editorial; not execution time',
              'live_execution_performed':False,
              'artifacts':{name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in names}}
    (out/'media-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Rendered banner, GIF, static result card, text summary and provenance manifest.')


if __name__=='__main__':
    main()
