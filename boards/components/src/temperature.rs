// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Component for any Temperature sensor.
//!
//! Usage
//! -----
//! ```rust
//! let temp = TemperatureComponent::new(board_kernel, nrf52::temperature::TEMP)
//!     .finalize(components::temperature_component_static!());
//! ```

use capsules_extra::temperature::TemperatureSensor;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil;

#[macro_export]
macro_rules! temperature_component_static {
    ($T:ty $(,)?) => {{
        kernel::static_buf!(capsules_extra::temperature::TemperatureSensor<'static, $T>)
    };};
}

pub type TemperatureComponentType<T> = capsules_extra::temperature::TemperatureSensor<'static, T>;

pub struct TemperatureComponent<T: 'static + hil::sensors::TemperatureDriver<'static>> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    temp_sensor: &'static T,
}

impl<T: 'static + hil::sensors::TemperatureDriver<'static>> TemperatureComponent<T> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        temp_sensor: &'static T,
    ) -> TemperatureComponent<T> {
        TemperatureComponent {
            board_kernel,
            driver_num,
            temp_sensor,
        }
    }
}

impl<T: 'static + hil::sensors::TemperatureDriver<'static>> Component for TemperatureComponent<T> {
    type StaticInput = &'static mut MaybeUninit<TemperatureSensor<'static, T>>;
    type Output = &'static TemperatureSensor<'static, T>;

    fn finalize(self, s: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        let temp = s.write(TemperatureSensor::new(
            self.temp_sensor,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
        ));

        hil::sensors::TemperatureDriver::set_client(self.temp_sensor, temp);
        temp
    }
}
