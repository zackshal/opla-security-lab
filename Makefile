SHELL := /bin/bash
.DEFAULT_GOAL := help
export LAB_DIR
export THRESHOLD
THRESHOLD ?= 100
VM ?= victim
.PHONY: help bootstrap image up down ready ssh console xdp-deploy xdp-build xdp-load xdp-unload xdp-all xdp-test xdp-dashboard xdp-stats check monitoring-up monitoring-down monitoring-configure monitoring-start monitoring-stop versions
help:
	@echo 'Стенд: bootstrap image up ready ssh console down'
	@echo 'XDP: xdp-all xdp-unload xdp-test xdp-dashboard xdp-stats (THRESHOLD=100)'
	@echo 'Zabbix: monitoring-up monitoring-configure monitoring-start monitoring-stop monitoring-down'
	@echo 'Проверка: check versions. Выбор стенда: LAB_DIR=/run/opla/lab-...'
bootstrap:
	@./bootstrap.sh
image:
	@./bin/prepare-image.sh
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
