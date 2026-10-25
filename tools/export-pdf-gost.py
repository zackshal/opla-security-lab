#!/usr/bin/env python3
"""Публичная сборка PDF OPLA; закрытый ключ преподавателя не поддерживается.

PDF создаются отдельно от Git; после сборки файлы получают права 0600.
"""
import argparse
import html
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, KeepTogether, PageBreak, PageTemplate,
    Paragraph, Preformatted, Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents


R = Path(__file__).resolve().parents[1]
FONT_DIRS = [
    Path('/usr/share/fonts/truetype/liberation2'),
    Path('/usr/share/fonts/truetype/liberation'),
    Path('/usr/share/fonts/truetype/dejavu'),
]


def find_font(candidates):
    for directory in FONT_DIRS:
        for filename in candidates:
            path = directory / filename
            if path.exists():
                return path
    raise FileNotFoundError(
        "Не найден шрифт Liberation Serif или DejaVu Serif. "
        "Установите fonts-liberation либо fonts-dejavu-core."
    )


font_files = {
    'Serif': find_font([
        'LiberationSerif-Regular.ttf', 'DejaVuSerif.ttf'
    ]),
    'SerifBold': find_font([
        'LiberationSerif-Bold.ttf', 'DejaVuSerif-Bold.ttf'
    ]),
    'SerifItalic': find_font([
        'LiberationSerif-Italic.ttf', 'DejaVuSerif-Italic.ttf',
        'LiberationSerif-Regular.ttf', 'DejaVuSerif.ttf'
    ]),
    'SerifBoldItalic': find_font([
        'LiberationSerif-BoldItalic.ttf', 'DejaVuSerif-BoldItalic.ttf',
        'LiberationSerif-Bold.ttf', 'DejaVuSerif-Bold.ttf'
    ]),
    'Mono': find_font(['DejaVuSansMono.ttf']),
}
for font_name, font_path in font_files.items():
    pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
pdfmetrics.registerFontFamily(
    'Serif', normal='Serif', bold='SerifBold',
    italic='SerifItalic', boldItalic='SerifBoldItalic'
)

# ГОСТ 7.32-2017: A4, поля 30/15/20/20 мм, основной текст >= 12 pt,
# межстрочный интервал 1,5 и абзацный отступ 1,25 см.
PAGE_WIDTH, PAGE_HEIGHT = A4
LEFT_MARGIN = 3 * cm
RIGHT_MARGIN = 1.5 * cm
TOP_MARGIN = 2 * cm
BOTTOM_MARGIN = 2 * cm
TEXT_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN
TEXT_HEIGHT = PAGE_HEIGHT - TOP_MARGIN - BOTTOM_MARGIN
TABLE_PART_MAX_HEIGHT = 620  # оставляем место для подписи и повторяемой шапки

STYLES = {
    'body': ParagraphStyle(
        'body', fontName='Serif', fontSize=12, leading=18,
        alignment=TA_JUSTIFY, firstLineIndent=1.25 * cm,
        spaceAfter=7, splitLongWords=True, textColor=colors.black,
        allowWidows=0, allowOrphans=0,
    ),
    'h1': ParagraphStyle(
        'h1', fontName='SerifBold', fontSize=15, leading=22,
        firstLineIndent=1.25 * cm, spaceBefore=16, spaceAfter=10,
        keepWithNext=True, textColor=colors.black,
    ),
    'h2': ParagraphStyle(
        'h2', fontName='SerifBold', fontSize=13, leading=19,
        firstLineIndent=1.25 * cm, spaceBefore=12, spaceAfter=8,
        keepWithNext=True, textColor=colors.black,
    ),
    'h3': ParagraphStyle(
        'h3', fontName='SerifBold', fontSize=12, leading=18,
        firstLineIndent=1.25 * cm, spaceBefore=10, spaceAfter=7,
        keepWithNext=True, textColor=colors.black,
    ),
    'structural': ParagraphStyle(
        'structural', fontName='SerifBold', fontSize=12, leading=18,
        alignment=TA_CENTER, spaceBefore=0, spaceAfter=12,
        keepWithNext=True, textColor=colors.black,
    ),
    'cell': ParagraphStyle(
        'cell', fontName='Serif', fontSize=9.5, leading=12.5,
        spaceAfter=0, splitLongWords=True, textColor=colors.black,
    ),
    'cellhead': ParagraphStyle(
        'cellhead', fontName='SerifBold', fontSize=9.5, leading=12.5,
        alignment=TA_CENTER, spaceAfter=0, splitLongWords=True,
        textColor=colors.black,
    ),
    'code': ParagraphStyle(
        'code', fontName='Mono', fontSize=7.5, leading=10.5,
        spaceBefore=5, spaceAfter=8,
        backColor=colors.HexColor('#f2f4f7'), borderPadding=6,
        textColor=colors.black,
    ),
    'caption': ParagraphStyle(
        'caption', fontName='Serif', fontSize=10, leading=14,
        alignment=TA_CENTER, spaceBefore=4, spaceAfter=10,
        textColor=colors.black,
    ),
    'tablecaption': ParagraphStyle(
        'tablecaption', fontName='Serif', fontSize=10, leading=14,
        alignment=TA_LEFT, leftIndent=0, firstLineIndent=0,
        spaceBefore=2, spaceAfter=6, keepWithNext=True,
        textColor=colors.black,
    ),
    'cover': ParagraphStyle(
        'cover', fontName='SerifBold', fontSize=21, leading=29,
        alignment=TA_CENTER, spaceAfter=20, textColor=colors.black,
    ),
    'covermeta': ParagraphStyle(
        'covermeta', fontName='Serif', fontSize=12, leading=18,
        alignment=TA_CENTER, spaceAfter=12, textColor=colors.black,
    ),
    'toc1': ParagraphStyle(
        'toc1', fontName='Serif', fontSize=10, leading=13,
        spaceBefore=3, textColor=colors.black,
    ),
    'toc2': ParagraphStyle(
        'toc2', fontName='Serif', fontSize=9.5, leading=12,
        spaceBefore=1, leftIndent=12, textColor=colors.black,
    ),
}


def inline(text):
    """Markdown-подмножество для ReportLab; сохраняет тире и даёт переносы по разделителям."""
    text = html.escape(text)
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)

    def code_markup(match):
        value = match.group(1)
        value = re.sub(r'([/._-])', r'\1&#8203;', value)
        return f'<font name="Mono">{value}</font>'

    text = re.sub(r'`([^`]+)`', code_markup, text)
    # Не разрывать имена файлов/ключи произвольно посередине: разрешить перенос
    # после естественных разделителей, например в monitoring/bridge.py.
    text = re.sub(
        r'([A-Za-z0-9])([/._-])(?=[A-Za-z0-9])',
        r'\1\2&#8203;', text
    )
    return text


def clean_heading_for_caption(heading):
    heading = re.sub(r'^\s*\d+(?:\.\d+)*[.)]?\s+', '', heading).strip()
    return heading.rstrip('.')


def normalize_figure_caption(caption):
    caption = caption.strip()
    caption = re.sub(
        r'^\s*Рисунок\s+(\d+)\s*[-–—]\s*',
        r'Рисунок \1 — ', caption
    )
    if not caption.lower().startswith('рисунок '):
        CONTEXT['figures'] += 1
        caption = f"Рисунок {CONTEXT['figures']} — {caption}"
    return caption


class Document(BaseDocTemplate):
    def __init__(self, path, title, toc_depth=2):
        super().__init__(
            str(path), pagesize=A4,
            leftMargin=LEFT_MARGIN, rightMargin=RIGHT_MARGIN,
            topMargin=TOP_MARGIN, bottomMargin=BOTTOM_MARGIN,
            title=title, author='Шалашов Захар',
        )
        self.toc_depth = toc_depth
        frame = Frame(
            self.leftMargin, self.bottomMargin, self.width, self.height,
            leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0
        )
        self.addPageTemplates(
            PageTemplate('main', frames=[frame], onPage=self.decorate)
        )
        self.heading_number = 0

    def decorate(self, canvas, doc):
        if doc.page > 1:
            canvas.setFont('Serif', 8)
            canvas.setFillColor(colors.black)
            canvas.drawString(
                self.leftMargin, PAGE_HEIGHT - 1.2 * cm,
                'OPLA / редакция 24.10.2026'
            )
            canvas.drawRightString(
                PAGE_WIDTH - self.rightMargin, PAGE_HEIGHT - 1.2 * cm,
                'Кандидат к итоговой приёмке'
            )
            canvas.setFont('Serif', 10)
            canvas.drawCentredString(PAGE_WIDTH / 2, 1.1 * cm, str(doc.page))

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name in ('h1', 'h2'):
            self.heading_number += 1
            key = f'heading-{self.heading_number}'
            self.canv.bookmarkPage(key)
            level = 0 if flowable.style.name == 'h1' else 1
            if level < self.toc_depth:
                self.notify(
                    'TOCEntry',
                    (level, flowable.getPlainText(), self.page, key)
                )

    def beforeDocument(self):
        self.heading_number = 0


CONTEXT = {'tables': 0, 'figures': 0, 'section': ''}


def table_style(table, row_count):
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e9eef5')),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#7f8996')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    return table


def make_table(data, widths):
    table = Table(data, colWidths=widths, repeatRows=1, hAlign='LEFT')
    return table_style(table, len(data))


def table_flow(rows):
    """Подпись слева; длинные таблицы разбиваются по строкам с явной пометкой продолжения."""
    ncols = max(map(len, rows))
    rows = [row + [''] * (ncols - len(row)) for row in rows]
    weights = [
        max(8, min(45, max(len(row[j]) for row in rows))) ** 0.7
        for j in range(ncols)
    ]
    widths = [TEXT_WIDTH * weight / sum(weights) for weight in weights]
    data = [
        [
            Paragraph(
                inline(cell),
                STYLES['cellhead'] if row_index == 0 else STYLES['cell']
            )
            for cell in row
        ]
        for row_index, row in enumerate(rows)
    ]

    CONTEXT['tables'] += 1
    table_number = CONTEXT['tables']
    title = clean_heading_for_caption(CONTEXT['section']) or 'Данные'
    first_caption = Paragraph(
        inline(f'Таблица {table_number} — {title}'),
        STYLES['tablecaption']
    )

    full_table = make_table(data, widths)
    full_height = full_table.wrap(TEXT_WIDTH, 10000)[1]
    if full_height <= TABLE_PART_MAX_HEIGHT:
        return [KeepTogether([
            first_caption, full_table, Spacer(1, 10)
        ])]

    # Не даём длинной таблице разрываться внутри строки. Части формируются
    # заранее; каждая следующая начинается с новой страницы и имеет подпись
    # «Продолжение таблицы N» согласно п. 6.6.3 ГОСТ 7.32-2017.
    header = data[0]
    body_rows = data[1:]
    chunks = []
    current = []
    for row in body_rows:
        candidate = make_table([header] + current + [row], widths)
        candidate_height = candidate.wrap(TEXT_WIDTH, 10000)[1]
        if current and candidate_height > TABLE_PART_MAX_HEIGHT:
            chunks.append(current)
            current = [row]
        else:
            current.append(row)
    if current:
        chunks.append(current)

    result = []
    for index, chunk in enumerate(chunks):
        caption = first_caption if index == 0 else Paragraph(
            inline(f'Продолжение таблицы {table_number}'),
            STYLES['tablecaption']
        )
        part = make_table([header] + chunk, widths)
        result.append(KeepTogether([caption, part, Spacer(1, 8)]))
        if index < len(chunks) - 1:
            result.append(PageBreak())
    return result


def add_code_block(flow, lines):
    wrapped_lines = []
    for source_line in lines:
        if not source_line:
            wrapped_lines.append('')
            continue
        pieces = textwrap.wrap(
            source_line, width=98, subsequent_indent='    ',
            replace_whitespace=False, drop_whitespace=False,
            break_long_words=True, break_on_hyphens=False,
        ) or ['']
        wrapped_lines.extend(pieces)

    # Делим только между небольшими группами строк и держим каждую группу
    # целиком, чтобы многострочные команды не ломались на границе страниц.
    chunks = [
        wrapped_lines[start:start + 18]
        for start in range(0, len(wrapped_lines), 18)
    ]
    for chunk in chunks:
        flow.append(KeepTogether([
            Preformatted('\n'.join(chunk), STYLES['code'])
        ]))


def add_paragraph(flow, text):
    paragraph = Paragraph(inline(text), STYLES['body'])
    _, height = paragraph.wrap(TEXT_WIDTH, 10000)
    # Короткие и средние абзацы остаются целиком на одной странице.
    if height <= TABLE_PART_MAX_HEIGHT:
        flow.append(KeepTogether([paragraph]))
    else:
        flow.append(paragraph)


def markdown(path):
    lines = path.read_text(encoding='utf-8').splitlines()
    flow = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line or line == '---':
            i += 1
            continue

        if line.startswith('```'):
            block = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                block.append(lines[i].rstrip())
                i += 1
            add_code_block(flow, block)
            i += 1
            continue

        if line.startswith('|'):
            raw_rows = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                row = [
                    cell.strip()
                    for cell in lines[i].strip().strip('|').split('|')
                ]
                if not all(re.fullmatch(r':?-+:?', cell) for cell in row):
                    raw_rows.append(row)
                i += 1
            if raw_rows:
                flow.extend(table_flow(raw_rows))
            continue

        heading = re.match(r'^(#{1,6})\s+(.*)', line)
        if heading:
            level = min(len(heading[1]), 3)
            style = f'h{level}'
            CONTEXT['section'] = heading[2]
            flow.append(Paragraph(inline(heading[2]), STYLES[style]))
            i += 1
            continue

        figure = re.match(r'!\[([^\]]*)\]\(([^)]+)\)', line)
        if figure:
            name = Path(figure[2]).stem
            png = R / 'release-artifacts/.figures' / (name + '.png')
            if png.exists():
                from PIL import Image as PILImage
                with PILImage.open(png) as source_image:
                    width, height = source_image.size
                scale = min(
                    TEXT_WIDTH / width,
                    (0.48 * TEXT_HEIGHT) / height
                )
                image_flowable = Image(
                    str(png), width=width * scale, height=height * scale
                )
                caption_text = normalize_figure_caption(figure[1])
                flow.append(KeepTogether([
                    image_flowable,
                    Paragraph(inline(caption_text), STYLES['caption'])
                ]))
            i += 1
            continue

        if re.match(r'^(?:[-*]|[0-9]+\.)\s+', line):
            add_paragraph(flow, line)
            i += 1
            continue

        chunk = [line]
        i += 1
        while (
            i < len(lines)
            and lines[i].strip()
            and lines[i].strip() != '---'
            and not re.match(
                r'^(#|\||```|!\[|[-*]\s|[0-9]+\.\s)',
                lines[i].strip()
            )
        ):
            chunk.append(lines[i].strip())
            i += 1
        add_paragraph(flow, ' '.join(chunk))

    return flow


SPECS = {
    'manual': (
        'OPLA_Lab_Manual.pdf',
        'Наблюдаемая защита HTTP-сервиса на Linux',
        'Методические указания и фонд оценочных средств',
        [
            'docs/methodology.md', 'docs/fos.md',
            'docs/software.md', 'docs/sources.md'
        ],
    ),
    'engineering': (
        'OPLA_Engineering_Report.pdf',
        'Архитектура и апробация OPLA',
        'Инженерный отчёт, модель угроз и протокол',
        [
            'docs/architecture.md', 'docs/security-model.md',
            'docs/metrics-catalog.md', 'docs/run-protocol.md',
            'docs/acceptance.md', 'docs/release.md'
        ],
    ),
    'portfolio': (
        'OPLA_Portfolio.pdf',
        'OPLA: безопасность компонентов Linux',
        'Проект для портфолио и демонстрации',
        ['docs/portfolio.md'],
    ),
}


def main():
    parser = argparse.ArgumentParser(
        description='Собрать личные PDF OPLA с оформлением по ГОСТ 7.32-2017'
    )
    parser.add_argument(
        '--out', type=Path, default=None,
        help='каталог публичных PDF (ключ преподавателя не поддерживается)'
    )
    parser.add_argument('--only', choices=list(SPECS))
    args = parser.parse_args()

    if args.out is None:
        args.out = R / 'release-artifacts/public'

    subprocess.run(
        [sys.executable, str(R / 'tools/make-figures.py')], check=True
    )
    args.out.mkdir(parents=True, exist_ok=True)

    for key, (filename, title, subtitle, paths) in SPECS.items():
        if args.only and key != args.only:
            continue

        story = [
            Spacer(1, 2 * cm),
            Paragraph('РТУ МИРЭА', STYLES['covermeta']),
            Spacer(1, cm),
            Paragraph(title, STYLES['cover']),
            Paragraph(subtitle, STYLES['covermeta']),
            Spacer(1, 1.5 * cm),
            Paragraph('Шалашов Захар / БББО-01-23', STYLES['covermeta']),
            Paragraph('Студент 4-го курса бакалавриата, направление «Информационная безопасность»', STYLES['covermeta']),
            Paragraph('Москва, 2026', STYLES['covermeta']),
            Spacer(1, cm),
            Paragraph(
                'Редакция 25.10.2026. Локально апробированное ядро; '
                'отдельные интеграционные проверки и чистая установка не подтверждены.',
                STYLES['covermeta']
            ),
            PageBreak(),
        ]

        if key != 'portfolio':
            toc = TableOfContents()
            toc.levelStyles = [STYLES['toc1'], STYLES['toc2']]
            story.extend([
                Paragraph('СОДЕРЖАНИЕ', STYLES['structural']),
                toc,
                PageBreak(),
            ])

        CONTEXT.update({'tables': 0, 'figures': 0, 'section': ''})
        for index, source_path in enumerate(paths):
            if index:
                # Каждый самостоятельный раздел/документ начинается с новой страницы.
                story.append(PageBreak())
            story.extend(markdown(R / source_path))

        output_path = args.out / filename
        Document(
            output_path, title,
            toc_depth=1 if key == 'engineering' else 2
        ).multiBuild(story)
        os.chmod(output_path, 0o600)
        print(output_path)


if __name__ == '__main__':
    main()
