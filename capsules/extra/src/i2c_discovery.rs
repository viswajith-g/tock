// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

// Author: Viswajith Govinda Rajan

use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;

use kernel::debug;
use kernel::hil::gpio::Client as GpioClient;
use kernel::hil::i2c::{Error as I2CError, I2CHwMasterClient, I2CMaster};
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks, Time};
use kernel::utilities::cells::{OptionalCell, TakeCell};

// Scan the full I2C address range (0x08 to 0x77)
const I2C_START_ADDR: u8 = 0x08;
const I2C_END_ADDR: u8 = 0x77;

// Timeout (ms) if a device does not respond
const I2C_TIMEOUT_MS: u32 = 1000;

pub struct I2CDeviceDiscovery<'a, I: I2CMaster<'a> + 'a, A: Alarm<'a> + 'a> {
    i2c_master: &'a I,
    timeout_alarm: &'a VirtualMuxAlarm<'a, A>,
    current_address: OptionalCell<u8>,
    scan_buffer: TakeCell<'static, [u8]>,
    backup_buffer: TakeCell<'static, [u8]>,
    attached_device_addresses: TakeCell<'static, [u8]>,
    device_count: OptionalCell<usize>,
    scanning: OptionalCell<bool>,
    operation_pending: OptionalCell<bool>,
}

impl<'a, I: I2CMaster<'a> + 'a, A: Alarm<'a> + 'a> I2CDeviceDiscovery<'a, I, A> {
    pub fn new(
        i2c_master: &'a I,
        timeout_alarm: &'a VirtualMuxAlarm<'a, A>,
        scan_buffer: &'static mut [u8],
        backup_buffer: &'static mut [u8],
        attached_device_addresses: &'static mut [u8],
    ) -> I2CDeviceDiscovery<'a, I, A> {
        I2CDeviceDiscovery {
            i2c_master,
            timeout_alarm,
            current_address: OptionalCell::empty(),
            scan_buffer: TakeCell::new(scan_buffer),
            backup_buffer: TakeCell::new(backup_buffer),
            attached_device_addresses: TakeCell::new(attached_device_addresses),
            device_count: OptionalCell::new(0),
            scanning: OptionalCell::new(false),
            operation_pending: OptionalCell::new(false),
        }
    }

    fn start_scan(&self) {
        if self.scanning.get().unwrap_or(false) {
            debug!("[Warning] Scan already in progress");
            return;
        }

        debug!("[Log] Starting I2C Address Scan");

        self.device_count.set(0);
        if let Some(devices) = self.attached_device_addresses.take() {
            for i in 0..devices.len() {
                devices[i] = 0;
            }
            self.attached_device_addresses.replace(devices);
        }

        self.scanning.set(true);
        self.current_address.set(I2C_START_ADDR);
        self.scan_next_address();
    }

    fn scan_next_address(&self) {
        if let Some(addr) = self.current_address.get() {
            if addr > I2C_END_ADDR {
                debug!("[Log] I2C Address Range Scan Complete");
                self.display_results();
                self.scanning.set(false);
                return;
            }

            debug!("[Log] Testing address 0x{:02X}...", addr);

            if let Some(buffer) = self.scan_buffer.take() {
                self.start_timeout();

                match self.i2c_master.read(addr, buffer, 1) {
                    //match self.i2c_master.write(addr, buffer, 0) {
                    Ok(()) => {
                        debug!("  I2C write started for 0x{:02X}", addr);
                        self.operation_pending.set(true);
                    }
                    Err((read_error, buffer)) => {
                        debug!(
                            "  Read failed for 0x{:02X}, trying write: {:?}",
                            addr, read_error
                        );

                        // If read fails, try write
                        match self.i2c_master.write(addr, buffer, 0) {
                            Ok(()) => {
                                debug!("  I2C write started for 0x{:02X}", addr);
                                self.operation_pending.set(true);
                            }
                            Err((write_error, buffer)) => {
                                debug!("  Both read and write failed for 0x{:02X}: Read={:?}, Write={:?}",
                                             addr, read_error, write_error);
                                self.scan_buffer.replace(buffer);
                                self.cancel_timeout();
                                self.move_to_next_address();
                            }
                        }
                    }
                }
            } else {
                // Retry backup buffer
                if let Some(backup) = self.backup_buffer.take() {
                    self.scan_buffer.replace(backup);
                    debug!("  Using backup buffer for 0x{:02X}", addr);
                    self.scan_next_address();
                } else {
                    debug!("  No buffers available, skipping remaining addresses");
                    self.current_address.set(I2C_END_ADDR + 1);
                    self.scan_next_address();
                }
            }
        }
    }

    fn move_to_next_address(&self) {
        if let Some(addr) = self.current_address.get() {
            self.current_address.set(addr + 1);
            self.schedule_next_scan();
        }
    }

    fn schedule_next_scan(&self) {
        let delay_ms = 50;
        let delay_ticks = self.timeout_alarm.ticks_from_ms(delay_ms);
        self.timeout_alarm
            .set_alarm(self.timeout_alarm.now(), delay_ticks);
    }

    fn start_timeout(&self) {
        let timeout_ticks = self.timeout_alarm.ticks_from_ms(I2C_TIMEOUT_MS);
        self.timeout_alarm
            .set_alarm(self.timeout_alarm.now(), timeout_ticks);
    }

    fn cancel_timeout(&self) {
        let _ = self.timeout_alarm.disarm();
        self.operation_pending.set(false);
    }

    fn handle_timeout(&self) {
        if self.operation_pending.get().unwrap_or(false) {
            if let Some(addr) = self.current_address.get() {
                debug!("  [TIMEOUT] No response from 0x{:02X}", addr);

                // Handle buffer recovery
                if self.scan_buffer.is_none() {
                    if let Some(backup) = self.backup_buffer.take() {
                        self.scan_buffer.replace(backup);
                    }
                }

                self.operation_pending.set(false);
                self.move_to_next_address();
            }
        } else {
            self.scan_next_address();
        }
    }

    fn record_found_device(&self, address: u8) {
        if let Some(devices) = self.attached_device_addresses.take() {
            let count = self.device_count.get().unwrap_or(0);
            if count < devices.len() {
                devices[count] = address;
                self.device_count.set(count + 1);
                debug!("  FOUND DEVICE at address 0x{:02X}!", address);
            }
            self.attached_device_addresses.replace(devices);
        }
    }

    fn display_results(&self) {
        let count = self.device_count.get().unwrap_or(0);

        debug!("[Log] I2C Address Range Scan Results");

        if count > 0 {
            debug!("[Log] Found {} I2C device(s):", count);
            if let Some(devices) = self.attached_device_addresses.take() {
                for i in 0..count {
                    debug!("  Device at address: 0x{:02X}", devices[i]);
                }
                self.attached_device_addresses.replace(devices);
            }
        } else {
            debug!("[Log] No I2C devices found");
        }
    }

    // pub fn force_stop_scan(&self) {
    //    debug!("[Log] Force stopping I2C scan...");
    //     self.cancel_timeout();
    //     self.scanning.set(false);
    //     self.operation_pending.set(false);
    //     self.display_results();
    // }
}

impl<'a, I: I2CMaster<'a> + 'a, A: Alarm<'a> + 'a> GpioClient for I2CDeviceDiscovery<'a, I, A> {
    fn fired(&self) {
        if self.scanning.get().unwrap_or(false) {
            debug!("[Log] Scanning already in progress");
            // self.force_stop_scan();
        } else {
            debug!("[Log] Button pressed - starting full I2C address scan!");
            self.start_scan();
        }
    }
}

impl<'a, I: I2CMaster<'a> + 'a, A: Alarm<'a> + 'a> AlarmClient for I2CDeviceDiscovery<'a, I, A> {
    fn alarm(&self) {
        self.handle_timeout();
    }
}

impl<'a, I: I2CMaster<'a> + 'a, A: Alarm<'a> + 'a> I2CHwMasterClient
    for I2CDeviceDiscovery<'a, I, A>
{
    fn command_complete(&self, buffer: &'static mut [u8], status: Result<(), I2CError>) {
        self.cancel_timeout();
        self.scan_buffer.replace(buffer);

        if let Some(addr) = self.current_address.get() {
            match status {
                Ok(()) => {
                    debug!("  SUCCESS: Device responded at 0x{:02X}", addr);
                    self.record_found_device(addr);
                }
                Err(I2CError::AddressNak) => {
                    debug!("  No device at 0x{:02X}", addr);
                }
                Err(I2CError::DataNak) => {
                    debug!("  Device at 0x{:02X} (Data NAK)", addr);
                    self.record_found_device(addr);
                }
                Err(other_error) => {
                    debug!("  Error at 0x{:02X}: {:?}", addr, other_error);
                }
            }

            self.move_to_next_address();
        }
    }
}
