// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Capsule to scan I2C bus for attached devices on GPIO interrupt.
//!
//! This assumes the I2C bus is virtualized via `virtual_i2c::I2CDevice`.
//! It attempts a zero-length write + 1-byte read to all 7-bit addresses and logs those that respond.

use core::cell::Cell;

use kernel::debug;
use kernel::hil::gpio::{Client as GpioClient, FloatingState, InterruptEdge, InterruptPin};
use kernel::hil::i2c::{Error as I2CError, I2CClient, I2CDevice};
use kernel::utilities::cells::{OptionalCell, TakeCell};

/// Syscall driver number.
use capsules_core::driver;
pub const DRIVER_NUM: usize = driver::NUM::I2CDeviceScanner as usize;

pub const BUF_LEN: usize = 4;

/// Notifies kernel-side client of discovered devices and when scan completes.
pub trait I2CDeviceScanClient {
    fn device_found(&self, address: u8);
    fn scan_complete(&self);
}

/// Scans the I2C bus for active devices when a GPIO interrupt is triggered.
pub struct I2CDeviceScanner<'a, I: I2CDevice + 'static, P: InterruptPin<'static> + 'static> {
    i2c: &'a I,
    irq_pin: &'a P,
    buffer: TakeCell<'static, [u8]>,
    current_addr: Cell<u8>,
    scan_client: OptionalCell<&'static dyn I2CDeviceScanClient>,
}

impl<'a, I: I2CDevice + 'static, P: InterruptPin<'static> + 'static> I2CDeviceScanner<'a, I, P> {
    pub fn new(i2c: &'a I, irq_pin: &'a P, buffer: &'static mut [u8]) -> Self {
        Self {
            i2c,
            irq_pin,
            buffer: TakeCell::new(buffer),
            current_addr: Cell::new(0),
            scan_client: OptionalCell::empty(),
        }
    }

    /// Sets a kernel-side client to be notified on device discovery.
    pub fn set_client(&self, client: &'static dyn I2CDeviceScanClient) {
        self.scan_client.set(client);
    }

    /// Starts listening for the GPIO interrupt.
    pub fn start(&self) {
        self.irq_pin.make_input();
        self.irq_pin.set_floating_state(FloatingState::PullUp);
        self.irq_pin.enable_interrupts(InterruptEdge::FallingEdge);
    }

    /// Begins a scan from 0x03 to 0x77.
    fn start_scan(&self) {
        self.current_addr.set(0x03);
        debug!("[i2c-scan] triggered by GPIO interrupt");
        self.scan_next();
    }

    /// Attempts to contact the next I2C address.
    fn scan_next(&self) {
        debug!("scanning i2c line");
        let addr = self.current_addr.get();
        debug!("current address: {:?}", addr);
        if addr > 0x77 {
            debug!("[i2c-scan] complete");
            self.scan_client.map(|client| client.scan_complete());
            return;
        }

        self.buffer.take().map(|buf| {
            let res = self.i2c.write_read(buf, 0, 1);
            if res.is_err() {
                debug!("[i2c-scan] write_read failed at 0x{:02X}", addr);
            }
        });

        self.current_addr.set(addr + 1);
    }
}

impl<I: I2CDevice + 'static, P: InterruptPin<'static> + 'static> GpioClient
    for I2CDeviceScanner<'_, I, P>
{
    fn fired(&self) {
        self.start_scan();
    }
}

impl<I: I2CDevice + 'static, P: InterruptPin<'static> + 'static> I2CClient
    for I2CDeviceScanner<'_, I, P>
{
    fn command_complete(&self, buffer: &'static mut [u8], result: Result<(), I2CError>) {
        debug!("[i2c-scan] command_complete callback fired");

        let scanned_addr = self.current_addr.get() - 1;

        if result.is_ok() {
            debug!("[i2c-scan] found device at 0x{:02X}", scanned_addr);
            self.scan_client
                .map(|client| client.device_found(scanned_addr));
        }

        self.buffer.replace(buffer);
        self.scan_next();
    }
}
