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
