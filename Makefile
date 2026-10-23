SHELL := /bin/bash

# Активная лаба (самая свежая)
LAB_DIR ?= $(shell ls -dt /tmp/lab-*/ 2>/dev/null | head -1)
LAB_DIR := $(patsubst %/,%,$(LAB_DIR))

# IP из state.env (пусто, если лабы нет)
VICTIM_IP   := $(shell grep VICTIM_IP   $(LAB_DIR)/state.env 2>/dev/null | cut -d= -f2)
ATTACKER_IP := $(shell grep ATTACKER_IP $(LAB_DIR)/state.env 2>/dev/null | cut -d= -f2)
CLIENT_IP   := $(shell grep CLIENT_IP   $(LAB_DIR)/state.env 2>/dev/null | cut -d= -f2)

.PHONY: help bootstrap up down ssh console xdp-build xdp-deploy xdp-load xdp-unload xdp-test xdp-dashboard xdp-all xdp-clean

help:
	@echo "=== Стенд ==="
	@echo "  make bootstrap       — скачать базовые образы"
	@echo "  make up              — запустить стенд (sudo)"
	@echo "  make down            — остановить стенд (sudo)"
	@echo "  make ssh VM=victim   — SSH в ВМ"
	@echo "  make console VM=...  — serial-консоль"
	@echo "=== XDP ==="
	@echo "  make xdp-build       — собрать .o на victim (через SSH)"
	@echo "  make xdp-deploy      — только скопировать исходники на victim"
	@echo "  make xdp-load        — загрузить XDP на ens3"
	@echo "  make xdp-unload      — выгрузить XDP"
	@echo "  make xdp-test        — hping3 с attacker + счётчики"
	@echo "  make xdp-dashboard   — TUI-дашборд (SSH → bpftool)"
	@echo "  make xdp-all         — deploy + build + load"
	@echo "  make xdp-clean       — unload + очистить /tmp/xdp-build"

bootstrap:
	@./bootstrap.sh

up:
	@sudo ./bin/create-lab.sh

down:
	@[[ -n "$(LAB_DIR)" ]] || { echo "Нет активной лабы"; exit 1; }
	@sudo ./bin/cleanup-lab.sh "$(LAB_DIR)"

ssh:
	@[[ -n "$(VM)" ]] || { echo "Укажите VM=attacker|victim|client"; exit 1; }
	@./bin/ssh.sh "$(LAB_DIR)" "$(VM)"

console:
	@[[ -n "$(VM)" ]] || { echo "Укажите VM=attacker|victim|client"; exit 1; }
	@./bin/console.sh "$(LAB_DIR)" "$(VM)"

# ============================================================
# XDP
# ============================================================
xdp-deploy:
	@[[ -n "$(VICTIM_IP)" ]] || { echo "Нет активной лабы"; exit 1; }
	@cd xdp && ./deploy.sh "$(VICTIM_IP)"

xdp-build:
	@[[ -n "$(VICTIM_IP)" ]] || { echo "Нет активной лабы"; exit 1; }
	@cd xdp && ./build.sh "$(VICTIM_IP)"

xdp-load:
	@[[ -n "$(VICTIM_IP)" ]] || { echo "Нет активной лабы"; exit 1; }
	@cd xdp && ./load.sh "$(VICTIM_IP)"

xdp-unload:
	@[[ -n "$(VICTIM_IP)" ]] || { echo "Нет активной лабы"; exit 1; }
	@cd xdp && ./unload.sh "$(VICTIM_IP)"

xdp-test:
	@[[ -n "$(VICTIM_IP)" && -n "$(ATTACKER_IP)" ]] || { echo "Нет активной лабы"; exit 1; }
	@cd xdp && ./test.sh "$(ATTACKER_IP)" "$(VICTIM_IP)"

xdp-dashboard:
	@[[ -n "$(VICTIM_IP)" ]] || { echo "Нет активной лабы"; exit 1; }
	@cd xdp && ./dashboard.py "$(VICTIM_IP)"

xdp-all: xdp-deploy xdp-build xdp-load
	@echo "✅ XDP собран и загружен на $(VICTIM_IP)"

xdp-clean:
	@[[ -n "$(VICTIM_IP)" ]] || exit 0
	@cd xdp && ./unload.sh "$(VICTIM_IP)" 2>/dev/null || true
	@ssh -i "$$HOME/.ssh/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		student@"$(VICTIM_IP)" "rm -rf /tmp/xdp-build"
	@echo "✅ Очищено"
