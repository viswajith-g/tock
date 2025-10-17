/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Tock Contributors 2025.                                  */

/* Board-specific linker script for nRF52840DK secure bootloader */

/* Memory layout for nRF52840:
 * Bootloader allocation:
 * - Bootloader Flash: 32KB (0x00000000 - 0x00007FFF)
 * - Bootloader RAM: 16KB (0x20000000 - 0x20003FFF)
 * 
 * Kernel starts at: 0x00008000 (32KB offset)
 */

MEMORY
{
  /* Bootloader occupies first 32KB of flash */
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 32K
  
  /* Bootloader uses first 32KB of RAM */
  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 16K
}

/* Include common bootloader linker script */
INCLUDE ../../bootloader_layout.ld