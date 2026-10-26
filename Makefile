SHELL := /bin/bash
.DEFAULT_GOAL := help
LAB_DIR ?= $(shell python3 bin/lab-cli.py current 2>/dev/null)
export LAB_DIR
export MAX_SOURCES
export THRESHOLD
THRESHOLD ?= 100
VM ?= victim
.PHONY: help bootstrap image up down ready ssh console xdp-deploy xdp-build xdp-load xdp-unload xdp-all xdp-test xdp-dashboard xdp-stats check monitoring-up monitoring-down monitoring-configure monitoring-start monitoring-stop versions
help:
	@python3 bin/opla-help.py help

.PHONY: manual help-full help-xdp help-vm labs lab-select lab-status nodes doctor
manual help-full help-xdp help-vm:
	@python3 bin/opla-help.py "$@"
labs:
	@python3 bin/lab-cli.py list
lab-select:
	@python3 bin/lab-cli.py select "$(LAB)"
lab-status nodes:
	@python3 bin/lab-cli.py nodes
doctor:
	@python3 bin/lab-cli.py doctor

# Safe lifecycle of existing labs: no qcow2 deletion.
.PHONY: lab-start lab-stop lab-stack-down lab-infra-status
lab-start:
	@sudo python3 bin/lab-lifecycle.py start --lab "$(LAB_DIR)"
lab-stop:
	@bash monitoring/manage.sh monitoring-stop
	@sudo python3 bin/lab-lifecycle.py stop --lab "$(LAB_DIR)"
lab-infra-status:
	@sudo python3 bin/lab-lifecycle.py status --lab "$(LAB_DIR)"
# Zabbix/PostgreSQL are shared between labs; stop globally only when explicit.
lab-stack-down: lab-stop
	@bash monitoring/manage.sh monitoring-down
.PHONY: install uninstall lab-delete stack-down
# Only installs/removes a per-user CLI wrapper; not OS dependencies.
install:
	@python3 bin/opla-cli-install.py install
uninstall:
	@python3 bin/opla-cli-install.py uninstall
# Type the exact selected lab ID; this permanently deletes its VM disks.
lab-delete:
	@CONFIRM_LAB="$(CONFIRM_LAB)" bash bin/opla-lab-delete.sh
# Shared Zabbix/PostgreSQL: only use when other labs do not need them.
stack-down: lab-stack-down

bootstrap:
	@./bootstrap.sh
image:
	@./bin/prepare-image.sh "$(or $(ROLE),victim)"
up:
	@sudo ./bin/create-lab.sh
ready ssh console:
	@./bin/control.sh $@ "$(VM)"
# Legacy down deletes VM overlay disks. Require explicit acknowledgment.
down:
	@test "$(CONFIRM_DELETE)" = "yes" || { echo 'ОТКАЗ: make down удаляет каталог стенда и диски. Для удаления: make down CONFIRM_DELETE=yes LAB_DIR=/var/lib/opla/lab-...'; exit 2; }
	@./bin/control.sh down "$(VM)"
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

# Reproducible PDF artifacts. Public documents and private teacher key are separate.
DOCS_PYTHON ?= .venv-docs/bin/python
DOCS_PUBLIC_DIR ?= release-artifacts/public
DOCS_PRIVATE_DIR ?= $(HOME)/Documents/OPLA-private

.PHONY: docs-deps docs docs-teacher
docs-deps:
	@python3 -m venv .venv-docs
	@.venv-docs/bin/python -m pip install -r tools/requirements-docs.txt

docs:
	@$(DOCS_PYTHON) tools/export-pdf.py --out "$(DOCS_PUBLIC_DIR)"
	@echo "Public PDF documents: $(DOCS_PUBLIC_DIR)"

docs-teacher:
	@mkdir -p -m 700 "$(DOCS_PRIVATE_DIR)"
	@chmod 700 "$(DOCS_PRIVATE_DIR)"
	@$(DOCS_PYTHON) tools/export-pdf.py --only teacher --out "$(DOCS_PRIVATE_DIR)"
	@echo "Private teacher key: $(DOCS_PRIVATE_DIR)/OPLA_Teacher_Key.pdf"

# V5 Phase 1: inventory and secure-prune preview are strictly read-only.
.PHONY: resources prune
resources:
	@python3 bin/opla-resources.py resources $(if $(LAB),--lab "$(LAB)",)
prune:
	@python3 bin/opla-resources.py prune $(if $(LAB),--lab "$(LAB)",)

# V5.2: inspect persistent receipts. No destructive executor is exposed.
.PHONY: registry-status
registry-status:
	@python3 bin/opla-registry.py list
