# Установка и обновление CLI

Проверенный checkout устанавливается в отдельный root-owned destination через
`bin/opla-system-install.py --install --expected-sha256`. Рабочий checkout и
установленный snapshot не смешиваются.

## Обновление установленного CLI

Соберите новый snapshot, проверьте его hash и установите в новый destination;
после этого повторите read-only проверки. Не отключайте ownership и receipt
guards для обхода ошибки.
