// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! I/O operations for nRF52840DK bootloader

use secure_boot_common::BootloaderIO;

/// LEDs base address
const GPIO_P0_BASE: usize = 0x5000_0000;

/// LED register offsets
const GPIO_OUTSET_OFFSET: usize = 0x508;
const GPIO_OUTCLR_OFFSET: usize = 0x50C;
const GPIO_PIN_CNF_OFFSET: usize = 0x700;

/// LED pins on nRF52840DK
const LED1_PIN: u32 = 13; // P0.13
const LED2_PIN: u32 = 14; // P0.14
const LED3_PIN: u32 = 15; // P0.15
const LED4_PIN: u32 = 16; // P0.16

/// nRF52840DK I/O implementation
pub struct Nrf52840IO;

impl Nrf52840IO {
    /// Initialize GPIO for LED control
    pub fn new() -> Self {
        // Configure all LEDs as outputs
        unsafe {
            // LED1
            let pin_cnf_addr = GPIO_P0_BASE + GPIO_PIN_CNF_OFFSET + (LED1_PIN as usize * 4);
            core::ptr::write_volatile(pin_cnf_addr as *mut u32, 0x00000001); // DIR=Output
            
            // LED2
            let pin_cnf_addr = GPIO_P0_BASE + GPIO_PIN_CNF_OFFSET + (LED2_PIN as usize * 4);
            core::ptr::write_volatile(pin_cnf_addr as *mut u32, 0x00000001); // DIR=Output

            // LED3
            let pin_cnf_addr = GPIO_P0_BASE + GPIO_PIN_CNF_OFFSET + (LED3_PIN as usize * 4);
            core::ptr::write_volatile(pin_cnf_addr as *mut u32, 0x00000001); // DIR=Output

            // LED4
            let pin_cnf_addr = GPIO_P0_BASE + GPIO_PIN_CNF_OFFSET + (LED4_PIN as usize * 4);
            core::ptr::write_volatile(pin_cnf_addr as *mut u32, 0x00000001); // DIR=Output
            
            // Turn off all LEDs initially
            let outset_addr = GPIO_P0_BASE + GPIO_OUTSET_OFFSET;
            core::ptr::write_volatile(
                outset_addr as *mut u32,
                (1 << LED1_PIN) | (1 << LED2_PIN) | (1 << LED3_PIN) | (1 << LED4_PIN)
            );
        }
        
        Self
    }
    
    /// LED on
    fn led_on(&self, pin: u32) {
        unsafe {
            let outclr_addr = GPIO_P0_BASE + GPIO_OUTCLR_OFFSET;
            core::ptr::write_volatile(outclr_addr as *mut u32, 1 << pin);
        }
    }
    
    /// LED off
    fn led_off(&self, pin: u32) {
        unsafe {
            let outset_addr = GPIO_P0_BASE + GPIO_OUTSET_OFFSET;
            core::ptr::write_volatile(outset_addr as *mut u32, 1 << pin);
        }
    }
    
    /// Delay loop
    pub fn delay(&self, cycles: u32) {
        for _ in 0..cycles {
            cortex_m::asm::nop();
        }
    }

    /// Debug: Blink LED a specific number of times to indicate error codes
    pub fn debug_blink(&self, pin: u32, count: usize) {
        for _ in 0..count {
            self.led_on(pin);
            self.delay(1_000_000);
            self.led_off(pin);
            self.delay(1_000_000);
        }
        self.delay(5_000_000);
    }
}

impl BootloaderIO for Nrf52840IO {
    /// Signal success: Turn on LED1
    fn signal_success(&self) {
        self.led_on(LED1_PIN);
    }
    
    /// Signal failure: Blink LED4
    fn signal_failure(&self) {
        loop {
            self.led_on(LED4_PIN);
            self.delay(1_000_000);
            self.led_off(LED4_PIN);
            self.delay(1_000_000);
        }
    }

    fn debug_write(&self, _msg: &str) {}

    fn debug_blink(&self, _pin: u32, _count: usize) {
        self.debug_blink(_pin, _count);
    }

}