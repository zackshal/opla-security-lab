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

.PHONY: services-status
services-status:
	@python3 bin/opla-services.py

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
	@sudo python3 bin/opla-secure-lab-delete.py --lab "$(or $(LAB),$(notdir $(LAB_DIR)))" --confirm "$(CONFIRM_DELETE)"
.PHONY: lab-delete-plan
lab-delete-plan:
	@python3 bin/opla-lab-cleanup-plan.py --lab "$(or $(LAB),$(notdir $(LAB_DIR)))" $(if $(JSON),--json,)

# Shared Zabbix/PostgreSQL: only use when other labs do not need them.
stack-down: lab-stack-down

bootstrap:
	@./bootstrap.sh
image:
	@./bin/prepare-image.sh "$(or $(ROLE),victim)"
up:
	@if [ "$$(id -u)" -eq 0 ]; then \
		python3 bin/opla-create-launcher.py; \
	else \
		sudo python3 bin/opla-create-launcher.py; \
	fi
ready ssh console:
	@./bin/control.sh $@ "$(VM)"
# Legacy down deletes VM overlay disks. Require explicit acknowledgment.
down:
	@echo 'BLOCKED: legacy down bypasses ownership checks. Use make lab-delete-plan LAB=lab-... to inspect.' >&2
	@exit 2
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

.PHONY: engineering-check
engineering-check:
	@python3 -m unittest discover -s tests -p 'test_engineering_ledger.py' -v
	@python3 bin/opla-engineering-ledger.py evaluate
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

# v5.3: explicit read-only ownership verification. Never deletes host resources.
.PHONY: registry-verify prune-verified
registry-verify:
	@python3 bin/opla-registry-verify.py verify $(if $(LAB),--lab "$(LAB)",)
prune-verified:
	@python3 bin/opla-registry-verify.py plan $(if $(LAB),--lab "$(LAB)",)

# V5.4: explicitly scoped Docker monitoring inventory and irreversible purge.
.PHONY: monitoring-purge-plan purge-monitoring
monitoring-purge-plan:
	@python3 bin/opla-monitoring-prune.py plan
purge-monitoring:
	@python3 bin/opla-monitoring-prune.py purge --confirm "$(CONFIRM_PURGE)"

# v5.5: cross-lab resource collision audit (strictly read-only).
.PHONY: registry-audit
registry-audit:
	@python3 bin/opla-registry-audit.py $(if $(JSON),--json,)

# v5.7: assessments only; no deletion authorization. Requires root for protected journal.
.PHONY: lab-delete-record cleanup-journal
lab-delete-record:
	@sudo python3 bin/opla-cleanup-journal.py record --lab "$(or $(LAB),$(notdir $(LAB_DIR)))"
cleanup-journal:
	@sudo python3 bin/opla-cleanup-journal.py list

# v5.8: only fully deprovisioned offline labs, with verified receipt and confirmation.
.PHONY: lab-prune-offline-plan lab-prune-offline
lab-prune-offline-plan:
	@sudo python3 bin/opla-offline-prune.py plan --lab "$(LAB)"
lab-prune-offline:
	@sudo python3 bin/opla-offline-prune.py execute --lab "$(LAB)" --confirm "$(CONFIRM_PRUNE)"

# Confirm with make lab-delete LAB=lab-XXXXXXXX CONFIRM_DELETE=DELETE-LAB:lab-XXXXXXXX

.PHONY: lab-delete-verified-plan
lab-delete-verified-plan:
	@sudo python3 bin/opla-secure-lab-delete.py --plan --lab "$(or $(LAB),$(notdir $(LAB_DIR)))"

# v5.9.3: verified recovery of an already-offline failed creation only.
# Refuse all live QEMU/DHCP/network resources; no implicit destructive cleanup.
.PHONY: creation-rollback-plan creation-rollback
creation-rollback-plan:
	@sudo python3 bin/opla-creation-rollback.py plan --lab "$(LAB)"
creation-rollback:
	@sudo python3 bin/opla-creation-rollback.py execute --lab "$(LAB)" --confirm "$(CONFIRM_ROLLBACK)"

# v5.9.4: inspect incomplete ACTIVE creation only; no destructive executor.
.PHONY: creation-active-recovery-plan
creation-active-recovery-plan:
	@sudo python3 bin/opla-active-recovery-plan.py --lab "$(LAB)"

# v5.9.5: explicit recovery for an incompletely created laboratory.
# Requires typed confirmation; no shared Docker or monitoring operations.
.PHONY: creation-active-recover
creation-active-recover:
	@sudo python3 bin/opla-active-creation-recover.py --lab "$(LAB)" --confirm "$(CONFIRM_RECOVER)"

# Privileged integration tests; never run in the ordinary CI check.
.PHONY: check-integration
check-integration:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Run: sudo make check-integration" >&2; exit 2; \
	fi
	@unshare --net -- python3 tests/integration/test_active_recovery_live.py

.PHONY: automation-probe
automation-probe:
	@./bin/opla-automation.sh probe

.PHONY: automation-validate automation-guest automation-all

automation-validate:
	@./bin/opla-automation.sh validate

automation-guest:
	@./bin/opla-automation.sh guest

automation-all:
	@./bin/opla-automation.sh all

.PHONY: scenario-validate scenario-plan

scenario-validate:
	@python3 bin/opla-scenario.py validate "$(or $(SCENARIO),syn-scan-baseline)"

scenario-plan:
	@python3 bin/opla-scenario.py plan "$(or $(SCENARIO),syn-scan-baseline)"

.PHONY: scenario-simulate

scenario-simulate:
	@python3 bin/opla-scenario-runner.py simulate "$(or $(SCENARIO),syn-scan-baseline)"

# Scenario and experiment reporting entry points.
.PHONY: scenario-live-check scenario-live-run experiment-report experiment-compare incident-report

scenario-live-check:
	@test -n "$(LAB)" || { echo "Usage: make scenario-live-check LAB=lab-..."; exit 2; }
	@python3 bin/opla-scenario-live.py check "$(or $(SCENARIO),syn-scan-baseline)" --lab "$(LAB)"

scenario-live-run:
	@test -n "$(LAB)" || { echo "Usage: make scenario-live-run LAB=lab-... CONFIRM=..."; exit 2; }
	@python3 bin/opla-scenario-live.py run "$(or $(SCENARIO),syn-scan-baseline)" --lab "$(LAB)" --confirm "$(CONFIRM)"

experiment-report:
	@test -n "$(REPORT)" || { echo "Usage: make experiment-report REPORT=reports/scenario-syn-..."; exit 2; }
	@python3 bin/opla-experiment-report.py "$(REPORT)"

experiment-compare:
	@python3 bin/opla-experiment-compare.py --reports "$(or $(REPORTS),reports)" --format "$(or $(FORMAT),csv)"

incident-report:
	@test -n "$(REPORT)" || { echo "Usage: make incident-report REPORT=reports/scenario-syn-..."; exit 2; }
	@python3 bin/opla-incident-report.py "$(REPORT)" \
		$(if $(EVE),--eve "$(EVE)") \
		$(if $(SCAN_EVENTS),--scan-events "$(SCAN_EVENTS)")

.PHONY: experiment-bundle
experiment-bundle:
	@test -n "$(REPORT)" || { echo "Usage: make experiment-bundle REPORT=reports/scenario-..."; exit 2; }
	@python3 bin/opla-experiment-bundle.py "$(REPORT)"

.PHONY: monitoring-experiment-publish
monitoring-experiment-publish:
	@test -n "$(LAB)" || { echo "Missing LAB"; exit 2; }
	@test -n "$(REPORT)" || { echo "Missing REPORT"; exit 2; }
	@python3 monitoring/experiment-publish.py --lab "$(LAB)" --experiment "$(REPORT)" $(if $(DRY_RUN),--dry-run)

.PHONY: acceptance-check
acceptance-check:
	@python3 bin/opla-acceptance-check.py --check

# Pure fake adapters and private temporary journals; no VM/SSH/network.
.PHONY: acceptance-offline
acceptance-offline:
	@python3 -m unittest discover -s tests -p 'test_lifecycle_*.py' -v

.PHONY: ci-offline
ci-offline:
	@git diff --check
	@python3 -m compileall -q bin tests
	@python3 -m unittest -q tests.test_opla_platform tests.test_integration_readiness_docs
	@python3 bin/opla-platform.py --json >/tmp/opla-platform-capabilities.json
	@$(MAKE) acceptance-offline
	@$(MAKE) check

.PHONY: lab-configure
lab-configure:
	@test -n "$(LAB)" || { echo "BLOCKED: LAB required"; exit 2; }
	@test "$(LAB)" = "$(CONFIRM)" || { echo "BLOCKED: confirmation mismatch"; exit 2; }
	@sudo python3 bin/opla-lab-configure-launcher.py "$(LAB)" "$(CONFIRM)"

# P13: custom infrastructure manifest, strictly read-only.
.PHONY: deploy-validate deploy-plan
deploy-validate:
	@python3 bin/opla-deploy.py validate "$(MANIFEST)"

deploy-plan:
	@python3 bin/opla-deploy.py plan "$(MANIFEST)"

.PHONY: deploy-connectivity-plan
deploy-connectivity-plan:
	@python3 bin/opla-deploy.py connectivity-plan "$(MANIFEST)"

.PHONY: deploy-connectivity-check
deploy-connectivity-check:
	@python3 bin/opla-connectivity-check.py "$(MANIFEST)" $(if $(filter 1,$(CONNECT)),--connect,)
