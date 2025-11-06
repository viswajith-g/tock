// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! I/O operations for nRF52840DK bootloader
use secure_boot_common::BootloaderIO;

/// LEDs for debugging
const GPIO_P0_BASE: usize = 0x5000_0000;

const GPIO_OUTSET_OFFSET: usize = 0x508;
const GPIO_OUTCLR_OFFSET: usize = 0x50C;
const GPIO_PIN_CNF_OFFSET: usize = 0x700;

const LED1_PIN: u32 = 13; // P0.13
const LED2_PIN: u32 = 14; // P0.14
const LED3_PIN: u32 = 15; // P0.15
const LED4_PIN: u32 = 16; // P0.16

/// UART for debugging
const UARTE0_BASE: usize = 0x4000_2000;
const TASKS_STARTTX: *mut u32 = (UARTE0_BASE + 0x008) as *mut u32;
const TASKS_STOPTX: *mut u32 = (UARTE0_BASE + 0x00C) as *mut u32;
const EVENTS_ENDTX: *mut u32 = (UARTE0_BASE + 0x120) as *mut u32;
const ENABLE: *mut u32 = (UARTE0_BASE + 0x500) as *mut u32;
const PSEL_TXD: *mut u32 = (UARTE0_BASE + 0x50C) as *mut u32;
const PSEL_RXD: *mut u32 = (UARTE0_BASE + 0x514) as *mut u32;
const BAUDRATE: *mut u32 = (UARTE0_BASE + 0x524) as *mut u32;
const CONFIG: *mut u32 = (UARTE0_BASE + 0x56C) as *mut u32;
const TXD_PTR: *mut u32 = (UARTE0_BASE + 0x544) as *mut u32;
const TXD_MAXCNT: *mut u32 = (UARTE0_BASE + 0x548) as *mut u32;

// Timer for timestamping
const TIMER0_BASE: usize = 0x40008000;
const TIMER_TASKS_START: usize = TIMER0_BASE + 0x000;
const TIMER_TASKS_CAPTURE0: usize = TIMER0_BASE + 0x040;
const TIMER_MODE: usize = TIMER0_BASE + 0x504;
const TIMER_BITMODE: usize = TIMER0_BASE + 0x508;
const TIMER_PRESCALER: usize = TIMER0_BASE + 0x510;
const TIMER_CC0: usize = TIMER0_BASE + 0x540;

/// nRF52840DK I/O implementation
pub struct Nrf52840IO;

impl Nrf52840IO {
    /// Initialize GPIO for LED control and UART debug
    pub fn new() -> Self {
        unsafe {
            for &pin in &[LED1_PIN, LED2_PIN, LED3_PIN, LED4_PIN] {
                let pin_cnf_addr = GPIO_P0_BASE + GPIO_PIN_CNF_OFFSET + (pin as usize * 4);
                core::ptr::write_volatile(pin_cnf_addr as *mut u32, 0x0000_0001); // DIR=Output
            }
            let outset_addr = GPIO_P0_BASE + GPIO_OUTSET_OFFSET;
            core::ptr::write_volatile(outset_addr as *mut u32,
                (1 << LED1_PIN) | (1 << LED2_PIN) | (1 << LED3_PIN) | (1 << LED4_PIN));

            // Initialize Timer0 for timestamps
            core::ptr::write_volatile(TIMER_MODE as *mut u32, 0); // Timer
            core::ptr::write_volatile(TIMER_BITMODE as *mut u32, 3); // 32-bit
            core::ptr::write_volatile(TIMER_PRESCALER as *mut u32, 4); // 1MHz
            core::ptr::write_volatile(TIMER_TASKS_START as *mut u32, 1);


            // Initialize UARTE for debug output
            core::ptr::write_volatile(ENABLE, 0);
            core::ptr::write_volatile(PSEL_TXD, 6);
            core::ptr::write_volatile(PSEL_RXD, 8);
            
            let tx_cnf = GPIO_P0_BASE + GPIO_PIN_CNF_OFFSET + (6 * 4);
            core::ptr::write_volatile(tx_cnf as *mut u32, 0x00000003);
            
            let rx_cnf = GPIO_P0_BASE + GPIO_PIN_CNF_OFFSET + (8 * 4);
            core::ptr::write_volatile(rx_cnf as *mut u32, 0x00000000);
            
            core::ptr::write_volatile(BAUDRATE, 0x01D7E000);
            
            core::ptr::write_volatile(CONFIG, 0x00000000);
            
            core::ptr::write_volatile(ENABLE, 8);
 
            for _ in 0..10_000 {
                core::arch::asm!("nop");
            }
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
    pub fn led_blink(&self, pin: u32, count: usize) {
        for _ in 0..count {
            self.led_on(pin);
            self.delay(1_000_000);
            self.led_off(pin);
            self.delay(1_000_000);
        }
        self.delay(5_000_000);
    }

    fn debug_write(&self, msg: &str) {
        // Copy to static buffer to ensure DMA can access it
        static mut UART_BUF: [u8; 256] = [0u8; 256];
        
        unsafe {
            let bytes = msg.as_bytes();
            let len = bytes.len().min(256);
            
            UART_BUF[..len].copy_from_slice(&bytes[..len]);
            
            let mut timeout = 100_000;
            while core::ptr::read_volatile(EVENTS_ENDTX) == 0 && timeout > 0 {
                cortex_m::asm::nop();
                timeout -= 1;
            }
            
            core::ptr::write_volatile(EVENTS_ENDTX, 0);
            core::ptr::write_volatile(TXD_PTR, UART_BUF.as_ptr() as u32);
            core::ptr::write_volatile(TXD_MAXCNT, len as u32);
            core::ptr::write_volatile(TASKS_STARTTX, 1);
            
            timeout = 100_000;
            while core::ptr::read_volatile(EVENTS_ENDTX) == 0 && timeout > 0 {
                cortex_m::asm::nop();
                timeout -= 1;
            }
            
            core::ptr::write_volatile(TASKS_STOPTX, 1);
            
            for _ in 0..10_000 {
                cortex_m::asm::nop();
            }
        }
    }

    fn format_hex(&self, value: usize, buf: &mut [u8; 32]) {
        let hex_chars = b"0123456789abcdef";
        buf[0] = b'0';
        buf[1] = b'x';
        
        for i in 0..8 {
            let nibble = ((value >> (28 - i * 4)) & 0xF) as usize;
            buf[2 + i] = hex_chars[nibble];
        }
        
        self.debug_write(unsafe { core::str::from_utf8_unchecked(&buf[..10]) });
        
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

    fn debug(&self, msg: &str) {
        self.debug_write(msg);
        self.debug_write("\r\n");
    }

    fn debug_blink(&self, pin: u32, count: usize) {
        self.led_blink(pin, count);
    }

    fn format(&self, value: usize, buf: &mut [u8; 32]) {
        self.format_hex(value, buf);
        self.debug_write("\r\n");
    }

    /// Get current timestamp in microseconds
    fn now_us(&self) -> u32 {
        unsafe {
            // Trigger capture to CC[0]
            core::ptr::write_volatile(TIMER_TASKS_CAPTURE0 as *mut u32, 1);
            // Read captured value
            core::ptr::read_volatile(TIMER_CC0 as *const u32)
        }
    }

    fn print_elapsed(&self, label: &str, start: u32) {
        let end = self.now_us();
        let elapsed = end.wrapping_sub(start);
        
        self.debug_write(label);
        
        // Choose appropriate unit
        let (value, unit) = if elapsed >= 1_000_000 {
            (elapsed / 1_000_000, " s")
        } else if elapsed >= 1_000 {
            (elapsed / 1_000, " ms")
        } else {
            (elapsed, " us")
        };
        
        // Simple decimal conversion
        let mut buf = [0u8; 32];
        let mut n = value;
        let mut i = 0;
        
        if n == 0 {
            buf[0] = b'0';
            i = 1;
        } else {
            while n > 0 {
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
                i += 1;
            }
            buf[..i].reverse();
        }
        
        self.debug_write(unsafe { core::str::from_utf8_unchecked(&buf[..i]) });
        self.debug_write(unit);
        self.debug_write("\r\n");
    }
}