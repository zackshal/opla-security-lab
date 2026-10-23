from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'tools/build-docs.py').read_text()
prefix=source.split("markdown(OUT/'methodology.md')")[0]
prefix=prefix.replace('Защита учебного HTTP сервера от SYN flood средствами eBPF и XDP','Наблюдение за XDP стендом в Zabbix и проведение испытаний')
prefix=prefix.replace('Методические указания','Руководство и протокол апробации')
ns={'__file__':str(ROOT/'tools/build-docs.py')};exec(prefix,ns)
D=ns['D'];OUT=ns['OUT'];markdown=ns['markdown'];qn=ns['qn']
markdown(OUT/'zabbix-guide.md')
D.add_page_break();D.add_heading('Приложение А Протокол апробации',1)
markdown(OUT/'run-protocol.md')
cleanup=source.split('# Remove template decorations and theme fonts, including inherited title rules.')[1].split("D.save(")[0]
exec(cleanup,ns)
D.save(OUT/'Руководство_Zabbix_и_протокол.docx')
print('Supplement saved')
