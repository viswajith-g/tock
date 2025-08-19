// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

// Author: Viswajith Govinda Rajan

use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
use capsules_extra::i2c_discovery::I2CDeviceDiscovery;
use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::hil::gpio::{FloatingState, Interrupt, Pin};
use kernel::hil::i2c::I2CMaster;
use kernel::hil::time::Alarm;

#[macro_export]
macro_rules! hardware_i2c_scanner_component_static {
    ($I: ty, $A: ty $(,)?) => {{
        use kernel::static_buf;
        let scan_buffer = static_buf!([u8; 1]);
        let backup_buffer = static_buf!([u8; 1]);
        let attached_device_addresses = static_buf!([u8; 20]);
        let device_discovery =
            static_buf!(capsules_extra::i2c_discovery::I2CDeviceDiscovery<'static, $I, $A>);

        (
            scan_buffer,
            backup_buffer,
            attached_device_addresses,
            device_discovery,
        )
    };};
}

pub struct I2CDiscoveryComponent<
    I: I2CMaster<'static> + 'static,
    A: kernel::hil::time::Alarm<'static> + 'static,
    P: Pin + Interrupt<'static> + 'static,
> {
    i2c_master: &'static I,
    timeout_alarm: &'static VirtualMuxAlarm<'static, A>,
    button_pin: &'static P,
}

impl<
        I: I2CMaster<'static> + 'static,
        A: kernel::hil::time::Alarm<'static> + 'static,
        P: Pin + Interrupt<'static> + 'static,
    > I2CDiscoveryComponent<I, A, P>
{
    pub fn new(
        i2c_master: &'static I,
        timeout_alarm: &'static VirtualMuxAlarm<'static, A>,
        button_pin: &'static P,
    ) -> I2CDiscoveryComponent<I, A, P> {
        I2CDiscoveryComponent {
            i2c_master,
            timeout_alarm,
            button_pin,
        }
    }
}

impl<
        I: I2CMaster<'static> + 'static,
        A: kernel::hil::time::Alarm<'static> + 'static,
        P: Pin + Interrupt<'static> + 'static,
    > Component for I2CDiscoveryComponent<I, A, P>
{
    type StaticInput = (
        &'static mut MaybeUninit<[u8; 1]>,
        &'static mut MaybeUninit<[u8; 1]>,
        &'static mut MaybeUninit<[u8; 20]>,
        &'static mut MaybeUninit<I2CDeviceDiscovery<'static, I, A>>,
    );
    type Output = &'static I2CDeviceDiscovery<'static, I, A>;

    fn finalize(self, s: Self::StaticInput) -> Self::Output {
        let buffer = s.0.write([0; 1]);
        let backup_buffer = s.1.write([0; 1]);
        let attached_device_addresses = s.2.write([0; 20]);
        let device_discovery = s.3.write(I2CDeviceDiscovery::new(
            self.i2c_master,
            self.timeout_alarm,
            buffer,
            backup_buffer,
            attached_device_addresses,
        ));

        self.i2c_master.set_master_client(device_discovery);

        self.timeout_alarm.set_alarm_client(device_discovery);

        self.button_pin.make_input();
        self.button_pin.set_floating_state(FloatingState::PullUp);
        self.button_pin
            .enable_interrupts(kernel::hil::gpio::InterruptEdge::FallingEdge);

        device_discovery
    }
}
