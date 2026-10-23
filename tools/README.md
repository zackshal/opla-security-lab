# Пересборка методички

Из корня проекта:

```bash
python3 -m venv .venv-docs
.venv-docs/bin/pip install -r tools/requirements-docs.txt
.venv-docs/bin/python tools/build-docs.py
libreoffice --headless --convert-to pdf --outdir docs docs/Методические_указания_ОПЛКА_XDP.docx
```

Нужен шрифт DejaVu Sans по пути /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
(в Debian пакет fonts-dejavu-core). Для Times New Roman при отсутствии локального
шрифта офисный пакет выбирает замену; после экспорта проверьте все страницы.
DOCX хранит редактируемый текст и таблицы, рисунки дополнительно есть в SVG.
Для пересборки нужны пакеты python3-venv, LibreOffice Writer и шрифты; они
не требуются для запуска самого стенда.
