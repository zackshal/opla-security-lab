# Резервирование и восстановление

**Русский** · [English](backup-restore.en.md)

## Что сохраняет каждый механизм

| Механизм | Сохраняет | Не гарантирует |
|---|---|---|
| Git bundle / source archive | Историю или выбранные исходники | VM RAM, диски, БД, приватные runtime secrets |
| QMP savevm | RAM и поддерживаемое состояние дисков одной работающей ВМ | Атомарное состояние всей группы ВМ и внешней PostgreSQL |
| Offline VM backup | Standalone qcow2, seed ISO и состояние стенда | Возможность запуска без восстановления сети/launcher; целостность приложений без опыта |
| pg_dump -Fc | Схему и данные PostgreSQL | VM snapshots, SMTP secrets, внешний API token, состояние почтовой очереди |
| Копия secrets/queue | Файлы конфигурации и очереди | Безопасное хранение без шифрования и защиту от повторной доставки |

Snapshots внутри исходного qcow2 не являются независимой резервной копией. Копии храните отдельно от рабочего диска; приватные backup files не публикуются в репозитории.

## Подготовка выбранного стенда

```bash
export LAB_DIR="$(python3 bin/state.py --latest)"
printf '%s\n' "$LAB_DIR"
make monitoring-stop
```

Для согласованного опыта остановите активную генерацию трафика. При откате счётчики/часы меняются; monitoring должен быть остановлен до loadvm.

## QMP: сохранить, посмотреть, откатить, удалить

```bash
make vm-save VM=client TAG=before-change
make vm-snapshots VM=client
```

Проверка: создайте до snapshot файл-маркер в client, после snapshot измените его, затем выполните rollback:

```bash
make vm-load VM=client TAG=before-change ROLLBACK=yes
make ssh VM=client
```

Содержимое файла должно вернуться к исходному. `ROLLBACK=yes` подтверждает потерю изменений после snapshot. SSH-сессия может прерваться/потребовать повторного подключения. Затем:

```bash
make vm-delete VM=client TAG=before-change
make monitoring-start
```

Удаление snapshot освобождает его состояние и не откатывает ВМ. VM=all выполняет операции последовательно, не атомарно. Новый launcher нужен для QMP sockets. Состояние текущих ВМ можно прочитать:

```bash
sudo python3 bin/vm-state.py status --lab "$LAB_DIR" --vm all
```

## Offline copy дисков

В каждой ВМ сначала выполните штатное `sudo shutdown -h now` через `make ssh VM=attacker|victim|client`. После выхода всех QEMU проверьте:

```bash
lab_id="${LAB_DIR##*/}"
sudo systemctl show "qemu-$lab_id-attacker.service" \
  "qemu-$lab_id-victim.service" "qemu-$lab_id-client.service" \
  -p Id -p ActiveState -p MainPID
```

MainPID должен быть 0 у всех трёх. `make down` не используется: он удаляет диски и весь каталог стенда.

```bash
mkdir -p "$HOME/opla-backups"
disk_backup_dir="$HOME/opla-backups/disks-$(date +%Y%m%d-%H%M%S)"
make vm-backup BACKUP_DIR="$disk_backup_dir"
```

В каталоге: standalone attacker/victim/client.qcow2, seed ISO, state.env и manifest.json с SHA-256 дисков. Команда откажет, если любая ВМ ещё работает. `qemu-img check` проверяет структуру qcow2, а не корректность содержимого nginx/БД. Root-owned backup с правами 0700 может требовать sudo для просмотра.

Вернуться к сохранённому стенду:

```bash
make vm-resume
make ready
```

После обычной загрузки проверьте/восстановите runtime state: XDP attachment, scan mode, Suricata, HTTP и collector. `vm-resume` требует сохранённых bridge/TAP/seed; это не восстановление после полной очистки сети или гарантированное восстановление после host reboot.

## Restore отдельного диска

Снова остановите все ВМ и collector. Укажите существующий backup явно:

```bash
make vm-restore VM=victim BACKUP_DIR="$disk_backup_dir" ROLLBACK=yes
make vm-resume
make ready
```

Команда проверяет hash/format, готовит staging image и сохраняет прежний диск как disk.before-restore-*.qcow2. Она восстанавливает только выбранный диск, а не всю сеть и не seed ISO. Старый диск не удаляйте до проверки загрузки и сервисов. Не переносите номера BPF program IDs между запусками.

## PostgreSQL dump

С работающей БД:

```bash
mkdir -p "$HOME/opla-backups"
db_backup_dir="$HOME/opla-backups/db-$(date +%Y%m%d-%H%M%S)"
make backup-db BACKUP_DIR="$db_backup_dir"
(cd "$db_backup_dir" && sha256sum -c SHA256SUMS)
```

Скрипт использует контейнер opla-monitoring-db-1 и PostgreSQL user/database zabbix. Dump не является резервной копией Docker volume на файловом уровне. `catalog.txt` показывает каталог архива; SHA256SUMS — контроль содержимого zabbix.dump.

## Restore drill в отдельную БД

```bash
bash tools/verify-db-backup.sh "$db_backup_dir"
```

Скрипт берёт точный image ID работающего PostgreSQL, создаёт временный контейнер с `--network none`, не публикует порт, монтирует только backup read-only и выполняет pg_restore --exit-on-error в новую opla_restore. Проверяет чтение hosts/items/triggers/dashboard, сохраняет приватный отчёт и удаляет только созданный контейнер с его anonymous volume по точному ID.

Рабочая БД и её volume не подключаются к этому контейнеру. Отказ SHA/restore завершает проверку ошибкой; restore log не печатается автоматически. Числа таблиц включают стандартные шаблоны Zabbix, а не только собственные объекты OPLA. После аварийного завершения процесса вне действия trap, например kill -9 или сбоя Docker daemon, временный контейнер может остаться: сначала идентифицируйте его ID, не запускайте массовый prune.

Эта проверка не заменяет запланированное восстановление рабочей БД. Для production restore сначала останавливают collector/alerts/server/web, сохраняют текущий volume/dump, проверяют совместимость PostgreSQL и роли и определяют допустимую потерю данных. Автоматической команды перезаписи рабочей БД здесь нет.

## Конфигурация, очередь и история

Для исходников:

```bash
umask 077
mkdir -p "$HOME/opla-backups"
git bundle create "$HOME/opla-backups/source-$(date +%Y%m%d-%H%M%S).bundle" --all
```

Bundle не включает незакоммиченные файлы. Почтовые secrets (`~/.config/opla/alerts.json`), очередь (`~/.local/state/opla-alerts`), monitoring/.env и приватный inventory сохраняйте отдельно в зашифрованное хранилище. Перед согласованной копией queue остановите opla-alerts.service; после её отката возможны повторные уведомления, уже принятые SMTP после момента backup.

Критерий успешного backup — проверенный restore, а не только существование архива. Зафиксируйте дату, source commit, manifest/hash, проверенный сценарий и место хранения независимой копии.
