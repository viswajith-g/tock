// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use cortexm4f::{
    initialize_ram_jump_to_main, nvic, scb, unhandled_interrupt, CortexM4F, CortexMVariant,
};

/*
 * Adapted from crt1.c which was relicensed by the original author from
 * GPLv3 to Apache 2.0.
 * The original version of the file, under GPL can be found at
 * https://github.com/SoftwareDefinedBuildings/stormport/blob/rebase0/tos/platforms/storm/stormcrt1.c
 *
 * Copyright 2016, Michael Andersen <m.andersen@eecs.berkeley.edu>
 */

extern "C" {
    // _estack is not really a function, but it makes the types work
    // You should never actually invoke it!!
    fn _estack();
}

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    link_section = ".vectors"
)]
// used Ensures that the symbol is kept until the final binary
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
/// ARM Cortex M Vector Table
pub static BASE_VECTORS: [unsafe extern "C" fn(); 16] = [
    // Stack Pointer
    _estack,
    // Reset Handler
    initialize_ram_jump_to_main,
    // NMI
    unhandled_interrupt,
    // Hard Fault
    CortexM4F::HARD_FAULT_HANDLER,
    // Memory Management Fault
    unhandled_interrupt,
    // Bus Fault
    unhandled_interrupt,
    // Usage Fault
    unhandled_interrupt,
    // Reserved
    unhandled_interrupt,
    // Reserved
    unhandled_interrupt,
    // Reserved
    unhandled_interrupt,
    // Reserved
    unhandled_interrupt,
    // SVCall
    CortexM4F::SVC_HANDLER,
    // Reserved for Debug
    unhandled_interrupt,
    // Reserved
    unhandled_interrupt,
    // PendSv
    unhandled_interrupt,
    // SysTick
    CortexM4F::SYSTICK_HANDLER,
];

#[cfg_attr(
    all(target_arch = "arm", target_os = "none"),
    link_section = ".vectors"
)]
// used Ensures that the symbol is kept until the final binary
#[cfg_attr(all(target_arch = "arm", target_os = "none"), used)]
pub static IRQS: [unsafe extern "C" fn(); 80] = [CortexM4F::GENERIC_ISR; 80];

#[no_mangle]
pub unsafe extern "C" fn init() {
    // Apply early initialization workarounds for anomalies documented on
    // 2015-12-11 nRF52832 Errata v1.2
    // http://infocenter.nordicsemi.com/pdf/nRF52832_Errata_v1.2.pdf

    // Workaround for Errata 12
    // "COMP: Reference ladder not correctly callibrated" found at the Errate doc
    *(0x40013540i32 as *mut u32) = (*(0x10000324i32 as *mut u32) & 0x1f00u32) >> 8i32;

    // Workaround for Errata 16
    // "System: RAM may be corrupt on wakeup from CPU IDLE" found at the Errata doc
    *(0x4007c074i32 as *mut u32) = 3131961357u32;

    // Workaround for Errata 31
    // "CLOCK: Calibration values are not correctly loaded from FICR at reset"
    // found at the Errata doc
    *(0x4000053ci32 as *mut u32) = (*(0x10000244i32 as *mut u32) & 0xe000u32) >> 13i32;

    // Only needed for preview hardware
    // // Workaround for Errata 32
    // // "DIF: Debug session automatically enables TracePort pins" found at the Errata doc
    // //    CoreDebug->DEMCR &= ~CoreDebug_DEMCR_TRCENA_Msk;
    // *(0xe000edfcu32 as (*mut u32)) &= !0x01000000,

    // Workaround for Errata 36
    // "CLOCK: Some registers are not reset when expected" found at the Errata doc
    //    NRF_CLOCK->EVENTS_DONE = 0;
    //    NRF_CLOCK->EVENTS_CTTO = 0;
    //    NRF_CLOCK->CTIV = 0;
    // }

    // Workaround for Errata 37
    // "RADIO: Encryption engine is slow by default" found at the Errata document doc
    *(0x400005a0i32 as *mut u32) = 0x3u32;

    // Workaround for Errata 57
    // "NFCT: NFC Modulation amplitude" found at the Errata doc
    *(0x40005610i32 as *mut u32) = 0x5u32;
    *(0x40005688i32 as *mut u32) = 0x1u32;
    *(0x40005618i32 as *mut u32) = 0x0u32;
    *(0x40005614i32 as *mut u32) = 0x3fu32;

    // Workaround for Errata 66
    // "TEMP: Linearity specification not met with default settings" found at the Errata doc
    //     NRF_TEMP->A0 = NRF_FICR->TEMP.A0;
    //     NRF_TEMP->A1 = NRF_FICR->TEMP.A1;
    //     NRF_TEMP->A2 = NRF_FICR->TEMP.A2;
    //     NRF_TEMP->A3 = NRF_FICR->TEMP.A3;
    //     NRF_TEMP->A4 = NRF_FICR->TEMP.A4;
    //     NRF_TEMP->A5 = NRF_FICR->TEMP.A5;
    //     NRF_TEMP->B0 = NRF_FICR->TEMP.B0;
    //     NRF_TEMP->B1 = NRF_FICR->TEMP.B1;
    //     NRF_TEMP->B2 = NRF_FICR->TEMP.B2;
    //     NRF_TEMP->B3 = NRF_FICR->TEMP.B3;
    //     NRF_TEMP->B4 = NRF_FICR->TEMP.B4;
    //     NRF_TEMP->B5 = NRF_FICR->TEMP.B5;
    //     NRF_TEMP->T0 = NRF_FICR->TEMP.T0;
    //     NRF_TEMP->T1 = NRF_FICR->TEMP.T1;
    //     NRF_TEMP->T2 = NRF_FICR->TEMP.T2;
    //     NRF_TEMP->T3 = NRF_FICR->TEMP.T3;
    //     NRF_TEMP->T4 = NRF_FICR->TEMP.T4;
    // }

    // Workaround for Errata 108
    // "RAM: RAM content cannot be trusted upon waking up from System ON Idle
    // or System OFF mode" found at the Errata doc
    *(0x40000ee4i32 as *mut u32) = *(0x10000258i32 as *mut u32) & 0x4fu32;

    // Explicitly tell the core where Tock's vector table is located. If Tock is the
    // only thing on the chip then this is effectively a no-op. If, however, there is
    // a bootloader present then we want to ensure that the vector table is set
    // correctly for Tock. The bootloader _may_ set this for us, but it may not
    // so that any errors early in the Tock boot process trap back to the bootloader.
    // To be safe we unconditionally set the vector table.
    scb::set_vector_table_offset(BASE_VECTORS.as_ptr().cast::<()>());

    nvic::enable_all();
}
