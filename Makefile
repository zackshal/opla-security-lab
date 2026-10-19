SHELL := /bin/bash
LAB_DIR ?= $(shell ls -dt /tmp/lab-* 2>/dev/null | head -1)

.PHONY: help bootstrap up down console ssh lint test clean

help:
	@echo "make bootstrap         — скачать базовые образы"
	@echo "make up                — запустить стенд (sudo)"
	@echo "make down              — остановить стенд (sudo)"
	@echo "make console VM=victim — serial-консоль ВМ"
	@echo "make ssh VM=victim     — SSH в ВМ"
	@echo "make lint              — shellcheck + yamllint"
	@echo "make test              — синтаксис скриптов"
	@echo "make clean             — удалить всё созданное"

bootstrap:
	@./bootstrap.sh

up:
	@sudo ./bin/create-lab.sh

down:
	@[[ -n "$(LAB_DIR)" ]] || { echo "Нет активной лабы"; exit 1; }
	@sudo ./bin/cleanup-lab.sh "$(LAB_DIR)"

console:
	@[[ -n "$(LAB_DIR)" ]] || { echo "Нет активной лабы"; exit 1; }
	@[[ -n "$(VM)" ]] || { echo "Укажите VM=attacker|victim|client"; exit 1; }
	@./bin/console.sh "$(LAB_DIR)" "$(VM)"

ssh:
	@[[ -n "$(LAB_DIR)" ]] || { echo "Нет активной лабы"; exit 1; }
	@[[ -n "$(VM)" ]] || { echo "Укажите VM=attacker|victim|client"; exit 1; }
	@./bin/ssh.sh "$(LAB_DIR)" "$(VM)"

lint:
	@command -v shellcheck >/dev/null && shellcheck bin/*.sh bootstrap.sh || echo "shellcheck не установлен"
	@command -v yamllint >/dev/null && yamllint cloud-init/*.yaml || echo "yamllint не установлен"

test:
	@bash -n bin/*.sh bootstrap.sh && echo "✅ синтаксис OK"

clean:
	@for d in /tmp/lab-*; do [[ -d "$$d" ]] && sudo ./bin/cleanup-lab.sh "$$d"; done 2>/dev/null || true
	@rm -f images/*.qcow2 images/*.iso
	@echo "Очищено"
