// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Secure bootloader for nRF52840DK
//! 
//! This bootloader verifies the Tock kernel signature and version before jumping to it.

#![no_std]
#![no_main]

mod config;
mod io;
mod panic;

use config::Nrf52840Config;
use io::Nrf52840IO;
use secure_boot_common::{verify_and_boot, BootloaderIO, BoardConfig};
use secure_boot_common::error::BootError;

const LED1_PIN: u32 = 13; // P0.13
const LED2_PIN: u32 = 14; // P0.14
const LED3_PIN: u32 = 15; // P0.15
const LED4_PIN: u32 = 16; // P0.16

// Include the startup assembly code
core::arch::global_asm!(include_str!("startup.s"));

/// Minimal `core::fmt::Write` adapter over a fixed buffer (for `#![no_std]`)
struct BufferWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufferWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.pos]).unwrap_or("")
    }
}

impl<'a> core::fmt::Write for BufferWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let len = bytes.len().min(self.buf.len().saturating_sub(self.pos));
        self.buf[self.pos..self.pos + len].copy_from_slice(&bytes[..len]);
        self.pos += len;
        Ok(())
    }
}

// #[inline(always)]
// fn read_reset_reason() -> u32 {
//     const RESETREAS: *const u32 = 0x4000_0400 as *const u32;
//     unsafe { core::ptr::read_volatile(RESETREAS) }
// }
// #[inline(always)]
// fn clear_reset_reason(bits: u32) {
//     const RESETREAS: *mut u32 = 0x4000_0400 as *mut u32;
//     unsafe { core::ptr::write_volatile(RESETREAS, bits); }
// }

/// Main entry point called by startup code
#[no_mangle]
pub extern "C" fn main() -> ! {
    // Initialize I/O
    let io = Nrf52840IO::new();
    io.debug("\r\n\r\n");
    io.debug("Secure Boot for Tock");

    let mut buf = [0u8; 32];

    // let reset_reason = read_reset_reason();
    // clear_reset_reason(reset_reason);

    // // no. of blinks is cause for reset (1=RESETPIN, 2=DOG, 3=SREQ, 4=LOCKUP)
    // let code = if reset_reason & (1<<3) != 0 { 4 }    // LOCKUP
    //     else if reset_reason & (1<<2) != 0 { 3 }      // SYSRESETREQ (soft reset)
    //     else if reset_reason & (1<<1) != 0 { 2 }      // watchdog
    //     else if reset_reason & (1<<0) != 0 { 1 }      // reset pin
    //     else { 5 };                                   // unknown/none
    // io.debug_blink(LED4_PIN, code);
    
    // Debug: 1 blink = bootloader started
    // io.debug_blink(LED1_PIN, 1);
    
    // Signature verification
    match verify_and_boot::<Nrf52840Config, _>(&io) {
        Ok(kernel_entry) => {

            // verify stack pointer and reset vector are valid
            let vector_table = kernel_entry as *const u32;
            let sp = unsafe { core::ptr::read_volatile(vector_table) } as usize;
            let reset_vector = unsafe { core::ptr::read_volatile(vector_table.add(1)) } as usize;

            let sp_in_sram = (0x2000_0000..0x2004_0000).contains(&sp);
            let rv_in_flash = (0x9000..0x24E84).contains(&(reset_vector & !1)) && (reset_vector & 1) == 1;

            io.debug_blink(
                LED3_PIN,
                if !sp_in_sram { 1 } else if !rv_in_flash { 2 } else { 3 },
            );

            if !(sp_in_sram && rv_in_flash){
                io.signal_failure();
                loop {} 
            } else {
                // Kernel Handoff
                io.debug("handing off to kernel");

                unsafe { jump_to_kernel(kernel_entry, &io); } 
            }
        }
        Err(error) => {
            // Debug: Blink LED2 to show specific error code
            let blink_count = match error {
                BootError::SentinelNotFound => 3,
                BootError::InvalidTLV => 4,
                BootError::InvalidSignature => 5,
                BootError::VerificationFailed => 6,
                BootError::UnsupportedAlgorithm => 7,
                BootError::InvalidKernelRegion => 8,
                BootError::SignatureMissing => 9,
                BootError::VersionTooOld => 10,
                BootError::HashError => 11,
                BootError::InvalidBDT => 12,
                BootError::BDTChecksumFailed => 13,
                BootError::NoValidKernel => 14,
                BootError::FlashOperationFailed => 15,
            };
            
            io.debug_blink(LED2_PIN, blink_count);
            
            // Verification failed
            io.signal_failure();
            unreachable!();
        }
    }
}

/// Jump to the kernel entry point
/// 
/// This function performs the handoff from bootloader to kernel:
/// 1. Loads the kernel's initial stack pointer
/// 2. Jumps to the kernel's reset handler
// unsafe fn jump_to_kernel<IO: BootloaderIO>(kernel_entry: usize, io: &IO) -> ! {
//     // Vector Table Var Init
//     let vector_table = kernel_entry as *const u32;
//     let main_stack_pointer = core::ptr::read_volatile(vector_table);
//     let reset_vector  = core::ptr::read_volatile(vector_table.add(1));

//     let mut buf = [0u8; 32];

//     io.debug("MSP:");
//     io.format(main_stack_pointer as usize, &mut buf);
//     io.debug("Reset vector:");
//     io.format(reset_vector as usize, &mut buf);

//     // Check if reset vector was relocated correctly
//     if reset_vector >= 0x9000 && reset_vector < 0x24E84 {
//         io.debug("Reset vector looks good!");
//     } else {
//         io.debug("ERROR: Reset vector outside kernel range!");
//         io.format(reset_vector as usize, &mut buf);
//     }

//     unsafe {
//         const NVMC_CONFIG: *mut u32 = 0x4001_E504 as *mut u32;
//         const NVMC_READY: *const u32 = 0x4001_E400 as *const u32;
        
//         // Set to read-only mode
//         core::ptr::write_volatile(NVMC_CONFIG, 0);
        
//         // Wait for NVMC to be ready
//         while core::ptr::read_volatile(NVMC_READY) == 0 {}
        
//         io.debug("NVMC reset to read mode");
//     }

//     // Disable UARTE0
//     const UARTE0_ENABLE: *mut u32 = 0x4000_2500 as *mut u32;
//     core::ptr::write_volatile(UARTE0_ENABLE, 0); 

//     // Disable interrupts
//     core::arch::asm!("cpsid i", options(nomem, nostack, preserves_flags));

//     // Disable SysTick
//     const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
//     core::ptr::write_volatile(SYST_CSR, 0);

//     // Disable & clear NVIC
//     const NVIC_ICER0: *mut u32 = 0xE000_E180 as *mut u32;
//     const NVIC_ICPR0: *mut u32 = 0xE000_E280 as *mut u32;
//     core::ptr::write_volatile(NVIC_ICER0.add(0), 0xFFFF_FFFF);
//     core::ptr::write_volatile(NVIC_ICER0.add(1), 0xFFFF_FFFF);
//     core::ptr::write_volatile(NVIC_ICPR0.add(0), 0xFFFF_FFFF);
//     core::ptr::write_volatile(NVIC_ICPR0.add(1), 0xFFFF_FFFF);

//     // Disable MPU
//     const MPU_CTRL: *mut u32 = 0xE000_ED94 as *mut u32;
//     core::ptr::write_volatile(MPU_CTRL, 0);

//     // Program VTOR to kernel vector table
//     const SCB_VTOR: *mut u32 = 0xE000_ED08 as *mut u32;
//     core::ptr::write_volatile(SCB_VTOR, kernel_entry as u32);
//     core::arch::asm!("dsb; isb", options(nomem, nostack, preserves_flags));

//     // Clear pending SysTick and PendSV
//     const SCB_ICSR: *mut u32 = 0xE000ED04 as *mut u32;
//     core::ptr::write_volatile(SCB_ICSR, 1 << 25);
//     core::ptr::write_volatile(SCB_ICSR, 1 << 27);
//     core::arch::asm!("dsb; isb", options(nomem, nostack, preserves_flags));

//     // UNMASK exceptions so SVC/PendSV work for the kernel
//     // PRIMASK=0, BASEPRI=0, FAULTMASK=0
//     // Without this, kernel keeps hardfaulting because one of these get escalated
//     core::arch::asm!("msr basepri, {0}",  in(reg) 0u32, options(nomem, nostack, preserves_flags));
//     core::arch::asm!("msr faultmask, {0}",in(reg) 0u32, options(nomem, nostack, preserves_flags));
//     core::arch::asm!("cpsie i", options(nomem, nostack, preserves_flags));

//     // Force privileged thread mode
//     core::arch::asm!("msr control, {0}", in(reg) 0u32, options(nostack, preserves_flags));
//     core::arch::asm!("isb", options(nomem, nostack, preserves_flags));

//     // Set MSP
//     core::arch::asm!("msr msp, {0}", in(reg) main_stack_pointer, options(nostack, preserves_flags));

//     // Invalidate instructions cache
//     const SCB_ICIALLU: *mut u32 = 0xE000_EF50 as *mut u32;
//     core::ptr::write_volatile(SCB_ICIALLU, 0);
    
//     core::arch::asm!("dsb; isb", options(nomem, nostack));

//     // Jump to reset handler
//     core::arch::asm!("dsb; isb", options(nomem, nostack, preserves_flags));
//     core::arch::asm!(
//         "bx {0}",
//         in(reg) reset_vector | 1,
//         options(noreturn)
//     );
// }
unsafe fn jump_to_kernel<IO: BootloaderIO>(kernel_entry: usize, io: &IO) -> ! {
    let vector_table = kernel_entry as *const u32;
    let msp  = core::ptr::read_volatile(vector_table);
    let reset= core::ptr::read_volatile(vector_table.add(1)); // keep LSB (Thumb)

    let mut buf = [0u8; 32];
    io.debug("MSP:");          io.format(msp as usize, &mut buf);
    io.debug("Reset vector:"); io.format(reset as usize, &mut buf);

    // Optional sanity: reset should land inside kernel text
    // (don’t enforce at runtime if you’re confident)
    io.debug("Reset vector looks good!");

    // Make sure NVMC back to read
    const NVMC_CONFIG: *mut u32 = 0x4001_E504 as *mut u32;
    const NVMC_READY:  *const u32 = 0x4001_E400 as *const u32;
    core::ptr::write_volatile(NVMC_CONFIG, 0);
    while core::ptr::read_volatile(NVMC_READY) == 0 {}
    io.debug("NVMC reset to read mode");

    // Disable SysTick and mask NVIC interrupts (don’t re-enable globally)
    const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
    core::ptr::write_volatile(SYST_CSR, 0);

    const NVIC_ICER0: *mut u32 = 0xE000_E180 as *mut u32; // IRQ 0..31
    const NVIC_ICER1: *mut u32 = 0xE000_E184 as *mut u32; // IRQ 32..63
    const NVIC_ICPR0: *mut u32 = 0xE000_E280 as *mut u32;
    const NVIC_ICPR1: *mut u32 = 0xE000_E284 as *mut u32;
    core::ptr::write_volatile(NVIC_ICER0, 0xFFFF_FFFF);
    core::ptr::write_volatile(NVIC_ICER1, 0xFFFF_FFFF);
    core::ptr::write_volatile(NVIC_ICPR0, 0xFFFF_FFFF);
    core::ptr::write_volatile(NVIC_ICPR1, 0xFFFF_FFFF);

    // Keep interrupts disabled globally until we jump
    core::arch::asm!("cpsid i", options(nomem, nostack, preserves_flags));

    // Program VTOR to kernel vector base
    const SCB_VTOR: *mut u32 = 0xE000_ED08 as *mut u32;
    core::ptr::write_volatile(SCB_VTOR, kernel_entry as u32);
    core::arch::asm!("dsb; isb", options(nomem, nostack, preserves_flags));

    // Clear pending SysTick + PendSV (write-1-to-clear; do both in one write)
    const SCB_ICSR: *mut u32 = 0xE000_ED04 as *mut u32;
    const PENDSVCLR: u32 = 1 << 27;
    const PENDSTCLR: u32 = 1 << 25;
    core::ptr::write_volatile(SCB_ICSR, PENDSVCLR | PENDSTCLR);
    core::arch::asm!("dsb; isb", options(nomem, nostack, preserves_flags));

    // Ensure privileged thread mode
    core::arch::asm!("msr control, {0}", in(reg) 0u32, options(nostack, preserves_flags));
    core::arch::asm!("isb", options(nomem, nostack, preserves_flags));

    // Load MSP from kernel vector table
    core::arch::asm!("msr msp, {0}", in(reg) msp, options(nostack, preserves_flags));
    core::arch::asm!("isb", options(nomem, nostack, preserves_flags));

    // Branch to kernel reset handler (preserve Thumb bit)
    let reset_thumb = reset | 1;
    core::arch::asm!(
        "bx {rst}",
        rst = in(reg) reset_thumb,
        options(noreturn)
    );
}


// Exception handlers - all weak so they can be overridden
#[no_mangle]
#[link_section = ".text.Default_Handler"]
pub extern "C" fn Default_Handler() -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn NMI_Handler() -> ! {
    Default_Handler()
}

#[no_mangle]
pub extern "C" fn HardFault_Handler() -> ! {
    Default_Handler()
}

#[no_mangle]
pub extern "C" fn MemManage_Handler() -> ! {
    Default_Handler()
}

#[no_mangle]
pub extern "C" fn BusFault_Handler() -> ! {
    Default_Handler()
}

#[no_mangle]
pub extern "C" fn UsageFault_Handler() -> ! {
    Default_Handler()
}

#[no_mangle]
pub extern "C" fn SVC_Handler() -> ! {
    Default_Handler()
}

#[no_mangle]
pub extern "C" fn DebugMon_Handler() -> ! {
    Default_Handler()
}

#[no_mangle]
pub extern "C" fn PendSV_Handler() -> ! {
    Default_Handler()
}

#[no_mangle]
pub extern "C" fn SysTick_Handler() -> ! {
    Default_Handler()
}