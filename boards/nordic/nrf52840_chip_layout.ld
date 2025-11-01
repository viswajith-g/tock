/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Tock Contributors 2023.                                  */

/* Memory Space Definitions, 1M flash, 256K ram */
MEMORY
{
  /* Kernel can be placed anywhere, but linked for address 0x0 */
  /* Bootloader will relocate at runtime */
  rom (rx)  : ORIGIN = 0x00009000, LENGTH = 964K
  ram (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}

PAGE_SIZE = 4K;
