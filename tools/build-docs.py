from pathlib import Path
import re,html,textwrap
from PIL import Image,ImageDraw,ImageFont
from docx import Document
from docx.shared import Cm,Pt,RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
R=Path(__file__).resolve().parents[1];OUT=R/'docs';FIG=OUT/'figures';FIG.mkdir(exist_ok=True)
ASSETS=OUT/'.render-assets';ASSETS.mkdir(exist_ok=True)
FONT='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
def diagram(name,nodes,edges,notes):
 w,h=1000,430
 im=Image.new('RGB',(w,h),'white');d=ImageDraw.Draw(im)
 font=ImageFont.truetype(FONT,18)
 svg=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}"><rect width="100%" height="100%" fill="white"/><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#333"/></marker></defs>']
 for x1,y1,x2,y2 in edges:
  d.line((x1,y1,x2,y2),fill='#333',width=2)
  import math
  a=math.atan2(y2-y1,x2-x1);pts=[(x2,y2),(x2-12*math.cos(a-.4),y2-12*math.sin(a-.4)),(x2-12*math.cos(a+.4),y2-12*math.sin(a+.4))];d.polygon(pts,fill='#333')
  svg.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#333" stroke-width="2" marker-end="url(#arrow)"/>')
 for x,y,nw,nh,lines in nodes:
  d.rounded_rectangle((x,y,x+nw,y+nh),radius=8,fill='#f4f4f4',outline='#333',width=2)
  svg.append(f'<rect x="{x}" y="{y}" width="{nw}" height="{nh}" rx="8" fill="#f4f4f4" stroke="#333"/>')
  for i,line in enumerate(lines):
   ty=y+nh/2+(i-(len(lines)-1)/2)*25
   d.text((x+nw/2,ty),line,font=font,fill='black',anchor='mm')
   svg.append(f'<text x="{x+nw/2}" y="{ty+6}" text-anchor="middle" font-family="DejaVu Sans,sans-serif" font-size="18">{html.escape(line)}</text>')
 for x,y,line in notes:
  d.text((x,y),line,font=font,fill='#333')
  svg.append(f'<text x="{x}" y="{y+18}" font-family="DejaVu Sans,sans-serif" font-size="18">{html.escape(line)}</text>')
 svg.append('</svg>');(FIG/(name+'.svg')).write_text('\n'.join(svg))
 im.save(ASSETS/(name+'.png'))
diagram('packet-path',[(20,90,180,90,['Входящий кадр']), (250,90,250,90,['Ethernet / VLAN','IPv4 / TCP']), (550,90,220,90,['SYN без ACK?']), (550,265,220,90,['Окно source IP','count += 1']), (815,245,165,70,['count ≤ 100','PASS']), (815,340,165,70,['count > 100','DROP'])],[(200,135,250,135),(500,135,550,135),(660,180,660,265),(770,290,815,280),(770,330,815,375)],[(795,110,'Прочее: PASS'),(555,220,'Да'),(20,340,'Длина и фрагменты'),(20,370,'проверяются до учёта SYN')])
diagram('topology',[(20,35,220,90,['attacker','.2 — SYN поток']), (390,35,220,90,['victim','.3 — Nginx / XDP']), (760,35,220,90,['client','.4 — HTTP']), (325,200,350,75,['Мост br-opN','пример 100.64.0.0/29']), (40,335,420,70,['Хост .1 — SSH и сборщик']), (605,335,350,70,['Zabbix + PostgreSQL','web 127.0.0.1:8080'])],[(130,125,390,200),(500,125,500,200),(870,125,610,200),(430,275,300,335),(460,370,605,370)],[(35,165,'ВМ общаются внутри /29'),(700,240,'Нет default route'),(700,270,'nft: наружу DROP')])

D=Document();sec=D.sections[0]
sec.page_width=Cm(21);sec.page_height=Cm(29.7)
sec.top_margin=Cm(2);sec.bottom_margin=Cm(2);sec.left_margin=Cm(3);sec.right_margin=Cm(1.5)
sec.different_first_page_header_footer=True
for name in ['Normal','Title','Heading 1','Heading 2','Heading 3','Caption']:
 st=D.styles[name];st.font.name='Times New Roman';st.font.size=Pt(12);st.font.color.rgb=RGBColor(0,0,0)
 st.paragraph_format.line_spacing=1.5
 if name=='Normal':st.paragraph_format.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY;st.paragraph_format.first_line_indent=Cm(1.25);st.paragraph_format.space_after=Pt(0)
for name in ['Heading 1','Heading 2','Heading 3']:
 st=D.styles[name];st.font.bold=True;st.paragraph_format.space_before=Pt(12);st.paragraph_format.space_after=Pt(6);st.paragraph_format.keep_with_next=True
D.styles['Title'].font.size=Pt(16)
f=sec.footer.paragraphs[0];f.alignment=WD_ALIGN_PARAGRAPH.CENTER
fld=OxmlElement('w:fldSimple');fld.set(qn('w:instr'),'PAGE');f._p.append(fld)
D.core_properties.title='Защита учебного HTTP сервера от SYN flood средствами eBPF и XDP'
D.core_properties.author='Шалашов Захар'
for text in ['РТУ МИРЭА','Практическая работа','Обнаружение предупреждение и ликвидация последствий компьютерных атак']:
 p=D.add_paragraph(text);p.alignment=WD_ALIGN_PARAGRAPH.CENTER;p.paragraph_format.first_line_indent=Cm(0);p.paragraph_format.space_after=Pt(16)
p=D.add_paragraph('Защита учебного HTTP сервера от SYN flood средствами eBPF и XDP',style='Title');p.alignment=WD_ALIGN_PARAGRAPH.CENTER;p.paragraph_format.space_before=Pt(32)
for text in ['Методические указания','Разработчик Шалашов Захар','Группа БББО 01 23','Москва 2026']:
 p=D.add_paragraph(text);p.alignment=WD_ALIGN_PARAGRAPH.CENTER;p.paragraph_format.first_line_indent=Cm(0);p.paragraph_format.space_before=Pt(14)
D.add_page_break()
def clean(s):return re.sub(r'\*\*|`','',s.strip())
def para(s,style=None):
 p=D.add_paragraph(clean(s),style=style);return p

def table(rows):
 t=D.add_table(rows=0,cols=len(rows[0]));t.autofit=False
 # Dense software inventory is typeset below as labelled paragraphs instead.
 total=16.5
 n=len(rows[0]);widths={2:[6,10.5],3:[4.3,6.1,6.1],4:[4,3.4,4.8,4.3],5:[3.1,4.1,3.5,3.2,2.6]}.get(n,[total/n]*n)
 for col,width in zip(t.columns,widths):col.width=Cm(width)
 for i,row in enumerate(rows):
  cells=t.add_row().cells
  for j,text in enumerate(row):
   cells[j].width=Cm(widths[j]);p=cells[j].paragraphs[0];p.paragraph_format.first_line_indent=Cm(0);p.paragraph_format.line_spacing=1.5;p.paragraph_format.space_after=Pt(3);p.paragraph_format.space_before=Pt(3)
   run=p.add_run(clean(text));run.font.size=Pt(12);run.bold=i==0
   tcPr=cells[j]._tc.get_or_add_tcPr();b=OxmlElement('w:tcBorders')
   for edge in ['top','left','bottom','right']:
    e=OxmlElement('w:'+edge);e.set(qn('w:val'),'single');e.set(qn('w:sz'),'4');e.set(qn('w:color'),'D9D9D9');b.append(e)
   tcPr.append(b)
   if i==0:
    shade=OxmlElement('w:shd');shade.set(qn('w:fill'),'EDEDED');tcPr.append(shade)
  if i==0:
   repeat=OxmlElement('w:tblHeader');t.rows[0]._tr.get_or_add_trPr().append(repeat)
  cant=OxmlElement('w:cantSplit');t.rows[-1]._tr.get_or_add_trPr().append(cant)
 D.add_paragraph()

def markdown(path,skip_title=True,software=False):
 lines=path.read_text().splitlines();i=0;code=False
 while i<len(lines):
  line=lines[i];i+=1
  if line.startswith('```'):code=not code;continue
  if code:
   p=D.add_paragraph();p.paragraph_format.first_line_indent=Cm(0);p.paragraph_format.alignment=WD_ALIGN_PARAGRAPH.LEFT;p.paragraph_format.line_spacing=1.5
   run=p.add_run(line);run.font.name='Courier New';run.font.size=Pt(12);continue
  if not line.strip():continue
  if line.startswith('# ') and skip_title:continue
  if path.name=='methodology.md' and (line.startswith('Практическая работа по') or line.startswith('Разработчик:')):continue
  if line.startswith('|'):
   rows=[line]
   while i<len(lines) and lines[i].startswith('|'):rows.append(lines[i]);i+=1
   rows=[[x.strip() for x in l.strip('|').split('|')] for l in rows if not re.match(r'^\|[- :|]+\|$',l)]
   if software and len(rows[0])==4 and rows[0][0].startswith('Средство'):
    for row in rows[1:]:
     p=para(row[0]);p.runs[0].bold=True;p.paragraph_format.keep_with_next=True
     para('Назначение: '+row[1]+'. Лицензия: '+row[2]+'.')
     p=para('Источник: '+row[3]);p.paragraph_format.first_line_indent=Cm(0);p.paragraph_format.space_after=Pt(6)
   else:table(rows)
   continue
  m=re.match(r'!\[(.*?)\]\(figures/(.*?)\.svg\)',line)
  if m:
   p=D.add_paragraph();p.paragraph_format.first_line_indent=Cm(0);p.alignment=WD_ALIGN_PARAGRAPH.CENTER;p.paragraph_format.keep_with_next=True
   p.add_run().add_picture(str(ASSETS/(m[2]+'.png')),width=Cm(16.5))
   p=para(m[1],'Caption');p.alignment=WD_ALIGN_PARAGRAPH.CENTER;continue
  if line.startswith('#'):
   level=min(3,len(line)-len(line.lstrip('#'))-1);D.add_heading(clean(line.lstrip('# ')),level=max(1,level));continue
  p=para('Перечень средств стенда' if software and line.startswith('Таблица 1') else line)
  if re.match(r'^Листинг \d+|^Таблица \d+',line):p.paragraph_format.keep_with_next=True
markdown(OUT/'methodology.md')
D.add_page_break();D.add_heading('Приложение Ж Фонд оценочных средств',1);markdown(OUT/'fos.md')
D.add_page_break();D.add_heading('Приложение И Программные средства',1);markdown(OUT/'software.md',software=True)
# Remove template decorations and theme fonts, including inherited title rules.
for style in D.styles:
    for node in list(style.element.iter(qn('w:pBdr'))): node.getparent().remove(node)
    if style.type == 1:
        style.font.name='Times New Roman'
        rf=style.element.find('.//'+qn('w:rFonts'))
        if rf is not None:
            for key in list(rf.attrib):
                if 'Theme' in key: del rf.attrib[key]
for p in D.paragraphs:
    for node in list(p._p.iter(qn('w:pBdr'))):node.getparent().remove(node)
D.save(OUT/'Методические_указания_ОПЛКА_XDP.docx')
print('Saved document')
