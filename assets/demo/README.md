# Демонстрационные материалы README

`overview.gif` — редакционная визуализация архитектуры и исторических наблюдений,
а не запись экрана. Числа взяты из [observed-results.json](observed-results.json),
который сохраняет переданный пользователем терминальный вывод от 24.10.2026.
SYN и HTTP — разные опыты. Длительности кадров произвольны; промежуточные
измерения, throughput, Suricata alerts и Zabbix screenshots не генерируются.

- [GIF](overview.gif), [статичный кадр](overview-poster.png).
- [Карточка результатов](results.png), [доступная текстовая версия](results.txt).
- [Manifest входных данных и media hashes](media-manifest.json).
- [Отдельная процессная CLI-демонстрация с synthetic evidence](services/README.md).
- [Исторический предыдущий replay](terminal-replay.gif).

Новый визуальный стиль: оригинальный SVG, отрисованные программно terminal
cards, отдельные панели экспериментов, высокий контраст и постоянно видимая
метка происхождения. Визуализация результатов не имитирует Zabbix dashboard.

Для повторной сборки нужны уже установленные Pillow и шрифты DejaVu:

```bash
python3 tools/build-demo.py
```

Команда выполняется из корня проекта и только рендерит локальные файлы.
VM, сеть, Docker, SSH и live endpoint не используются. Для другого output
доступен `--output /tmp/opla-readme-media`.

При оформлении README использованы структурные ориентиры:
[Doom Emacs](https://github.com/doomemacs/core) — навигация и prerequisites;
[HTTPie](https://github.com/httpie/cli) — заметная CLI-демонстрация и короткие примеры;
[Refine](https://github.com/refinedev/refine) — композиция баннера и блоков возможностей.
Их логотипы, картинки и тексты не копировались.

## Редакция оформления 30.10.2026

Светлая техническая палитра, русские подписи, тёмный блок сохранённого вывода,
самостоятельный текстовый результат и статичный вариант GIF. Числовые данные
остались в observed-results.json; источник и редакционный характер animation
показаны непосредственно на изображениях.

Ориентиры этой редакции:
[awesome-readme](https://github.com/matiassingers/awesome-readme) — ясное назначение,
TOC, демонстрации, FAQ и ссылка на развёрнутую документацию;
[awesome-readme-template](https://github.com/topics/awesome-readme-template) —
композиция первого экрана. Профильные виджеты, рейтинги и чужие иллюстрации
не включены в учебный проект. Все изображения создаются локальным renderer.
