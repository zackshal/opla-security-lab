SHELL := /bin/bash
.DEFAULT_GOAL := help
LAB_DIR ?= $(shell python3 bin/state.py --latest)
export LAB_DIR
export MAX_SOURCES
export THRESHOLD
THRESHOLD ?= 100
VM ?= victim
.PHONY: help bootstrap image up down ready ssh console xdp-deploy xdp-build xdp-load xdp-unload xdp-all xdp-test xdp-dashboard xdp-stats check monitoring-up monitoring-down monitoring-configure monitoring-start monitoring-stop versions
help:
	@echo 'Стенд: bootstrap image up ready ssh console down'
	@echo 'XDP: xdp-all xdp-unload xdp-test xdp-dashboard xdp-stats (THRESHOLD=100)'
	@echo 'Zabbix: monitoring-up monitoring-configure monitoring-start monitoring-stop monitoring-down'
	@echo 'Проверка: check versions. Выбор стенда: LAB_DIR=/var/lib/opla/lab-...'
bootstrap:
	@./bootstrap.sh
image:
	@./bin/prepare-image.sh "$(or $(ROLE),victim)"
up:
	@sudo ./bin/create-lab.sh
ready ssh console down:
	@./bin/control.sh $@ "$(VM)"
xdp-deploy:
	@./bin/control.sh deploy
xdp-build:
	@./bin/control.sh build
xdp-load:
	@./bin/control.sh load
xdp-unload:
	@./bin/control.sh unload
# Последовательные рецепты сохраняют порядок даже при make -j.
xdp-all:
	@./bin/control.sh deploy
	@./bin/control.sh build
	@./bin/control.sh load
xdp-test:
	@./bin/control.sh test
xdp-dashboard:
	@./bin/control.sh dashboard
xdp-stats:
	@./bin/control.sh collect
check:
	@python3 tests/check.py
monitoring-up monitoring-down monitoring-configure monitoring-start monitoring-stop:
	@./monitoring/manage.sh "$@"
versions:
	@./bin/versions.sh

.PHONY: vm-snapshots vm-save vm-load vm-delete vm-backup vm-restore vm-resume backup-db
vm-snapshots:
	@sudo python3 bin/vm-state.py list --lab "$(LAB_DIR)" --vm "$(VM)"
vm-save:
	@sudo python3 bin/vm-state.py save --lab "$(LAB_DIR)" --vm "$(VM)" --tag "$(TAG)"
vm-load:
	@sudo python3 bin/vm-state.py load --lab "$(LAB_DIR)" --vm "$(VM)" --tag "$(TAG)" $(if $(filter yes,$(ROLLBACK)),--confirm-rollback,)
vm-delete:
	@sudo python3 bin/vm-state.py delete --lab "$(LAB_DIR)" --vm "$(VM)" --tag "$(TAG)"
vm-backup:
	@sudo python3 bin/vm-disk.py backup --lab "$(LAB_DIR)" --directory "$(BACKUP_DIR)"
vm-restore:
	@sudo python3 bin/vm-disk.py restore --lab "$(LAB_DIR)" --directory "$(BACKUP_DIR)" --vm "$(VM)" $(if $(filter yes,$(ROLLBACK)),--confirm-restore,)
vm-resume:
	@sudo python3 bin/vm-disk.py resume --lab "$(LAB_DIR)"
backup-db:
	@bash bin/backup-db.sh "$(BACKUP_DIR)"

.PHONY: ids ips ids-off ids-status ids-test
ids:
	@bash bin/suricata.sh ids
ips:
	@bash bin/suricata.sh ips
ids-off:
	@bash bin/suricata.sh off
ids-status:
	@bash bin/suricata.sh status
ids-test:
	@bash bin/security-ids-test.sh

.PHONY: source-map
source-map:
	@bash bin/source-map.sh

# Public PDF outputs. Teacher answer keys are intentionally unsupported here.
.PHONY: docs docs-check check-docs
docs:
	@test -x .venv-docs/bin/python || { echo 'Run: python3 -m venv .venv-docs && .venv-docs/bin/python -m pip install -r tools/requirements-docs.txt' >&2; exit 1; }
	@.venv-docs/bin/python tools/export-pdf.py

check-docs:
	@python3 tools/check-docs.py

docs-check: check-docs docs
