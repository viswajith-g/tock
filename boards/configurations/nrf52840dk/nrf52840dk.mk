# Licensed under the Apache License, Version 2.0 or the MIT License.
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright Tock Contributors 2024.

# Shared makefile for building the tock kernel for nRF test boards.

# Path to signing tool
SIGN_KERNEL_DIR = $(TOCK_ROOT_DIRECTORY)tools/build/sign-kernel
SIGN_KERNEL = $(SIGN_KERNEL_DIR)/../../target/release/sign-kernel

# Build signing tool if it doesn't exist
$(SIGN_KERNEL):
	@echo "Building signing tool"
	cd $(SIGN_KERNEL_DIR) && cargo build --release

# Build the ELF, sign it, create the binary
$(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM).bin: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM) $(SIGN_KERNEL)
	@echo "Signing kernel ELF"
	$(SIGN_KERNEL) $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM)
	@echo "Creating binary from signed ELF"
	$(OBJCOPY) --output-target=binary --strip-sections --strip-all --remove-section .apps $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM) $@
	@$(SIZE) $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM)
	@sha256sum $@
TOCKLOADER=tockloader

# Where in the SAM4L flash to load the kernel with `tockloader`
KERNEL_ADDRESS=0x09000

# Upload programs over uart with tockloader
ifdef PORT
  TOCKLOADER_GENERAL_FLAGS += --port $(PORT)
endif

# Default target for installing the kernel.
.PHONY: install
install: flash

# Upload the kernel over JTAG
.PHONY: flash
flash: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM).bin
	$(TOCKLOADER) $(TOCKLOADER_GENERAL_FLAGS) flash --address $(KERNEL_ADDRESS) --board nrf52dk --jlink $<

# Upload the kernel over JTAG using OpenOCD
.PHONY: flash-openocd
flash-openocd: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM).bin
	$(TOCKLOADER) $(TOCKLOADER_GENERAL_FLAGS) flash --address $(KERNEL_ADDRESS) --board nrf52dk --openocd $<


# J-Link config
JLINK_EXE    ?= JLinkExe
JLINK_DEVICE ?= NRF52840_xxAA
JLINK_IF     ?= SWD
JLINK_SPEED  ?= 4000

.PHONY: flash-jlink
flash-jlink: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM).bin
	@echo "Flashing $(PLATFORM) to $(KERNEL_ADDRESS)"
	@SCRIPT=$$(mktemp /tmp/jlink_XXXXXX.jlink); \
	echo "r" > $$SCRIPT; \
	echo "loadbin $< $(KERNEL_ADDRESS)" >> $$SCRIPT; \
	echo "verifybin $< $(KERNEL_ADDRESS)" >> $$SCRIPT; \
	echo "r" >> $$SCRIPT; \
	echo "g" >> $$SCRIPT; \
	echo "q" >> $$SCRIPT; \
	cat $$SCRIPT; \
	$(JLINK_EXE) -device $(JLINK_DEVICE) -if $(JLINK_IF) -speed $(JLINK_SPEED) -autoconnect 1 -CommandFile $$SCRIPT || true; \
	rm -f $$SCRIPT
