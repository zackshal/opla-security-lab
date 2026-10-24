# Ansible: локальный хост и удалённый сервер

## Профили и границы

| Профиль | Playbook | Что устанавливает | Что остаётся отдельно |
|---|---|---|---|
| QEMU lab host | `ansible/lab-host.yml` | QEMU/libguestfs/network/build dependencies; Docker по отдельному разрешению | Образы, `make up/ready/xdp-all`, интерактивный Zabbix provisioning, почта |
| Security node | `ansible/site.yml` | Runtime packages, XDP/service units, Suricata IDS/HTTP IPS, nginx, Zabbix/PostgreSQL, local telemetry | Docker Compose, controller BPF object, VPN, серверный перенос lab scan-policy/poller |
| Preflight | `ansible/preflight.yml` | Ничего: проверяет prerequisites | Не проверяет verifier, реальное предотвращение и reboot |

Это автоматизация описанных операций, а не проверенная установка всего проекта одной командой на произвольной ОС. Живой отдельный сервер ещё не прошёл deployment/reboot/idempotence acceptance. `site.yml` требует Debian 13; `lab-host.yml` поддерживает подготовку Debian 12/13 amd64.

Ansible controller должен иметь Python/Ansible, исходники проекта и SSH-клиент. Target должен иметь Python 3 и sudo/become. Для local connection controller и target совпадают. Конкретная версия Ansible проверяется `ansible-playbook --version`; её не фиксировали в раннем протоколе.

## 1. Подготовка локального QEMU-хоста

Только на выделенной машине с доступным `/dev/kvm`:

```bash
ansible-playbook -i ansible/inventory.lab-local.example.ini \
  ansible/lab-host.yml --syntax-check

ansible-playbook -i ansible/inventory.lab-local.example.ini \
  ansible/lab-host.yml -K \
  -e opla_prepare_lab_host=true
```

Если Docker Compose уже есть, он не переустанавливается. Для действительно чистого хоста без Docker можно дополнительно передать `-e opla_install_docker=true`: добавится официальный Docker apt repository для текущего Debian и Docker CE/Compose. Не используйте этот флаг как способ миграции существующего стороннего Docker без отдельного плана.

Playbook не добавляет пользователей в docker group и не генерирует SSH-ключ. Настройте доступ оператора отдельно; членство в docker group даёт широкие root-полномочия. После подготовки следуйте root README: bootstrap → role images → up → ready. Проблема согласованной установки Suricata/libhtp2 в Debian 12 victim остаётся отмеченной в README и не исправляется подготовкой host packages.

## 2. Подготовка параметров server profile

Не запускайте `site.yml` на текущем рабочем lab host: он меняет nginx, vendor Suricata и BPF-привязку. Подходит отдельный Debian 13 security node с data interface, отличным от management/VPN.

```bash
umask 077
mkdir -p "$HOME/.config/opla/deploy"
cp ansible/vars.example.yml "$HOME/.config/opla/deploy/vars.yml"
cp ansible/inventory.example.ini "$HOME/.config/opla/deploy/hosts.ini"
```

В `vars.yml` заполните `opla_interface`, `opla_home_net`, `opla_host_name`, reviewed image tags и `opla_bpf_object`. Это путь к скомпилированному объекту на **controller**, не на target. Адреса 192.0.2.0/24 в примерах — документационные, не рабочая сеть. Не включайте `opla_allow_management_interface=true`, чтобы обойти случайно выбранный SSH/VPN-интерфейс.

Удалите строки `vault_db_password`/`vault_zabbix_password` из обычного vars.yml и создайте зашифрованный Vault:

```bash
ansible-vault create "$HOME/.config/opla/deploy/vault.yml"
```

В редакторе задайте два разных пароля: `vault_db_password` (не менее 24 символов из A–Z/a–z/0–9/_/-) и `vault_zabbix_password` (не менее 16, без CHANGE_). В shell команды секреты не вставляются. Пароль Vault храните отдельно от encrypted file. `--diff` при реальном запуске с секретами не используйте.

Docker Compose на target должен быть установлен заранее. Preflight явно проверяет это; server profile сам Docker не устанавливает. Для BPF object используйте reviewed CI package или локальную компиляцию с clang/libbpf headers. Проверьте `SHA256SUMS` распакованного CI package. Build metadata не заменяет verifier на целевом ядре.

## 3. Обычный SSH

В приватном hosts.ini:

```ini
[opla]
security-node ansible_host=192.0.2.10 ansible_user=operator ansible_connection=ssh ansible_python_interpreter=/usr/bin/python3
```

Замените адрес. Используйте существующий SSH agent/IdentityFile; приватный ключ не хранится в inventory и Git. Host key сверяется по доверенному каналу, а не отключением StrictHostKeyChecking.

```bash
ansible -i "$HOME/.config/opla/deploy/hosts.ini" opla \
  -m ansible.builtin.ping

ansible-playbook -i "$HOME/.config/opla/deploy/hosts.ini" \
  ansible/preflight.yml -K \
  -e "@$HOME/.config/opla/deploy/vars.yml"

ansible-playbook -i "$HOME/.config/opla/deploy/hosts.ini" \
  ansible/site.yml -K --ask-vault-pass \
  -e "@$HOME/.config/opla/deploy/vars.yml" \
  -e "@$HOME/.config/opla/deploy/vault.yml"
```

`ansible.builtin.ping` проверяет выполнение Python-модуля по соединению Ansible, а не ICMP reachability. После playbook проверьте реальные services, XDP, метрики и доступ с отдельного клиента.

## 4. SSH поверх VPN

VPN и SSH — разные уровни. VPN сначала создаёт маршрут до management address; Ansible затем подключается по SSH к этому адресу. Работающий Tor HTTP/SOCKS proxy не заменяет VPN и не является SSH-транспортом Ansible.

Для уже настроенного туннеля проверьте:

```bash
ip route get 10.66.0.10
ssh operator@10.66.0.10 true
```

Пример `ansible/inventory.vpn.example.ini` использует 10.66.0.10. Замените его своим management address и скопируйте inventory вне Git. Запуск preflight/site такой же, как для SSH. Настройка WireGuard/OpenVPN, выдача ключей и открытие firewall к VPN не автоматизированы этим проектом. Не включайте `opla_interface` равным wg0/tun0, если через него идёт управление.

Если GUI/Tor нужен только на controller, его proxy environment не направляет автоматически весь target apt/Docker трафик через VPN/Tor; сетевые зависимости target проверяются отдельно.

## 5. Bastion / jump host

Пример `ansible/inventory.jump.example.ini` задаёт `ProxyJump`. Проверьте ключи и host keys для обоих узлов. Это SSH через bastion, а не дополнительный агент Ansible на сервере. Для VPN+bastion используется тот же механизм с доступными через VPN адресами.

## 6. Локальное выполнение server profile без SSH

На отдельном Debian 13 security node можно использовать `ansible/inventory.local.example.ini`:

```bash
ansible-playbook -i ansible/inventory.local.example.ini \
  ansible/preflight.yml -K \
  -e "@$HOME/.config/opla/deploy/vars.yml"

ansible-playbook -i ansible/inventory.local.example.ini \
  ansible/site.yml -K --ask-vault-pass \
  -e "@$HOME/.config/opla/deploy/vars.yml" \
  -e "@$HOME/.config/opla/deploy/vault.yml"
```

Это установка server profile на текущую машину, не настройка QEMU lab. Проверьте, что локальные 8080/10051 и nginx не заняты другой установкой. Local connection не создаёт изоляцию от системы controller.

## 7. После развёртывания

```bash
sudo systemctl status opla-xdp opla-telemetry opla-suricata --no-pager
sudo bpftool net show
sudo bpftool prog show pinned /sys/fs/bpf/opla-server/program
sudo journalctl -u opla-telemetry -n 30 --no-pager
```

Server pins отличаются от lab pins: `/sys/fs/bpf/opla-server` против `/sys/fs/bpf/opla`. Lab scan-policy wrapper жёстко обращается к lab map: его нельзя считать готовой настройкой серверной scan policy. Пассивный Python sensor и Gmail/Proton poller из lab тоже не устанавливаются `site.yml` автоматически. Optional `vault_opla_mail` настраивает штатный Zabbix media type, а не Tor curl poller.

Повторный playbook, аварийная остановка engine, поведение management path, перезагрузка и откат требуют отдельных опытов. Syntax-check в CI не даёт этих гарантий.
