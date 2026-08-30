# SPDX-License-Identifier: GPL-3.0-or-later

POWERSHELL ?= pwsh
CONFIGURATION ?= debug

.DEFAULT_GOAL := all

.PHONY: all host kernel debug release clean test analyse sanitise deps image run boot-test fault-test storage-test zifs-test intel help

all:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Configuration $(CONFIGURATION) -Target all

host:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Configuration $(CONFIGURATION) -Target host

kernel:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Configuration $(CONFIGURATION) -Target kernel

debug:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Configuration debug -Target all

release:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Configuration release -Target all

clean:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/clean.ps1

test:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1 -Configuration $(CONFIGURATION)

analyse:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Configuration debug -Target analyse

sanitise:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1 -Configuration sanitised

deps:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/fetch_deps.ps1

image:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Configuration $(CONFIGURATION) -Target image

run:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/run_qemu.ps1 -Configuration $(CONFIGURATION)

boot-test:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1 -Configuration $(CONFIGURATION) -Boot

fault-test:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1 -Configuration $(CONFIGURATION) -Fault

storage-test:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1 -Configuration $(CONFIGURATION) -Storage

zifs-test:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1 -Configuration $(CONFIGURATION) -ZiFs

intel:
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Configuration $(CONFIGURATION) -Target intel

help:
	@$(POWERSHELL) -NoProfile -Command "Get-Content README.md | Select-Object -First 45"
