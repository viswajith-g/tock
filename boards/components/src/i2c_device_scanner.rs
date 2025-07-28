// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Component for I2C Device Scanner
//!
//! Usage:
//! ```rust
//! components::i2c_interrupt_scanner::I2cInterruptScannerComponent::new(i2c_dev, irq_pin)
//!     .finalize(components::i2c_interrupt_scanner_component_static!());
//! ```

use capsules_core::virtualizers::virtual_i2c::{I2CDevice, MuxI2C};
use capsules_extra::i2c_device_scanner::{I2CDeviceScanClient, I2CDeviceScanner};
use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::hil::{gpio::InterruptPin, i2c};

#[macro_export]
macro_rules! i2c_device_scanner_component_static {
    ($I:ty, $P:ty $(,)?) => {{
        let scanner = kernel::static_buf!(
            capsules_extra::i2c_device_scanner::I2CDeviceScanner<
                capsules_core::virtualizers::virtual_i2c::I2CDevice<$I>,
                $P,
            >
        );
        let buffer = kernel::static_buf!([u8; capsules_extra::i2c_device_scanner::BUF_LEN]);
        let i2c_device =
            kernel::static_buf!(capsules_core::virtualizers::virtual_i2c::I2CDevice<$I>);
        (scanner, buffer, i2c_device)
    }};
}

pub struct I2CDeviceScannerComponent<
    I: 'static + i2c::I2CMaster<'static>,
    P: InterruptPin<'static> + 'static,
> {
    i2c_mux: &'static MuxI2C<'static, I>,
    irq_pin: &'static P,
    address: u8,
    client: &'static dyn I2CDeviceScanClient,
}

impl<I: i2c::I2CMaster<'static>, P: InterruptPin<'static>> I2CDeviceScannerComponent<I, P> {
    pub fn new(
        i2c_mux: &'static MuxI2C<'static, I>,
        irq_pin: &'static P,
        address: u8,
        client: &'static dyn I2CDeviceScanClient,
    ) -> Self {
        Self {
            i2c_mux,
            irq_pin,
            address,
            client,
        }
    }
}

impl<I: i2c::I2CMaster<'static>, P: InterruptPin<'static>> Component
    for I2CDeviceScannerComponent<I, P>
{
    type StaticInput = (
        &'static mut MaybeUninit<I2CDeviceScanner<'static, I2CDevice<'static, I>, P>>,
        &'static mut MaybeUninit<[u8; capsules_extra::i2c_device_scanner::BUF_LEN]>,
        &'static mut MaybeUninit<I2CDevice<'static, I>>,
    );
    type Output = &'static I2CDeviceScanner<'static, I2CDevice<'static, I>, P>;

    fn finalize(self, static_input: Self::StaticInput) -> Self::Output {
        let i2c_dev = static_input
            .2
            .write(I2CDevice::new(self.i2c_mux, self.address));
        let buffer = static_input
            .1
            .write([0; capsules_extra::i2c_device_scanner::BUF_LEN]);

        let scanner = static_input
            .0
            .write(I2CDeviceScanner::new(i2c_dev, self.irq_pin, buffer));

        i2c_dev.set_client(scanner);
        self.irq_pin.set_client(scanner);
        scanner.set_client(self.client);

        scanner.start();
        scanner
    }
}
