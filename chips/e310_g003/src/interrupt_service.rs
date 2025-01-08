// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use crate::chip::E310xDefaultPeripherals;
use crate::interrupts;

#[repr(transparent)]
pub struct E310G003DefaultPeripherals<'a> {
    pub e310x: E310xDefaultPeripherals<'a>,
}

impl E310G003DefaultPeripherals<'_> {
    pub unsafe fn new(clock_frequency: u32) -> Self {
        Self {
            e310x: E310xDefaultPeripherals::new(clock_frequency),
        }
    }

    pub fn init(&'static self) {
        self.e310x.init();
    }
}
impl kernel::platform::chip::InterruptService for E310G003DefaultPeripherals<'_> {
    unsafe fn service_interrupt(&self, interrupt: u32) -> bool {
        match interrupt {
            interrupts::UART0 => self.e310x.uart0.handle_interrupt(),
            interrupts::UART1 => self.e310x.uart1.handle_interrupt(),
            int_pin @ interrupts::GPIO0..=interrupts::GPIO31 => {
                let pin = &self.e310x.gpio_port[(int_pin - interrupts::GPIO0) as usize];
                pin.handle_interrupt();
            }

            // put E310x specific interrupts here
            _ => return self.e310x.service_interrupt(interrupt),
        }
        true
    }
}
