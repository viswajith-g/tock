// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Components for using PWM.

use capsules_core::virtualizers::virtual_pwm::{MuxPwm, PwmPinUser};
use capsules_extra::pwm::Pwm;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil::pwm;

#[macro_export]
macro_rules! pwm_mux_component_static {
    ($A:ty $(,)?) => {{
        kernel::static_buf!(capsules_core::virtualizers::virtual_pwm::MuxPwm<'static, $A>)
    };};
}

#[macro_export]
macro_rules! pwm_pin_user_component_static {
    ($A:ty $(,)?) => {{
        kernel::static_buf!(capsules_core::virtualizers::virtual_pwm::PwmPinUser<'static, $A>)
    };};
}

#[macro_export]
macro_rules! pwm_driver_component_helper {
    ($($P:expr),+ $(,)?) => {{
        use kernel::count_expressions;
        use kernel::static_init;
        const NUM_DRIVERS: usize = count_expressions!($($P),+);

        let drivers = static_init!(
            [&'static dyn kernel::hil::pwm::PwmPin; NUM_DRIVERS],
            [
                $($P,)*
            ]
        );
        let pwm = kernel::static_buf!(capsules_extra::pwm::Pwm<'static, NUM_DRIVERS>);
        (pwm, drivers)
    };};
}

pub struct PwmMuxComponent<P: 'static + pwm::Pwm> {
    pwm: &'static P,
}

impl<P: 'static + pwm::Pwm> PwmMuxComponent<P> {
    pub fn new(pwm: &'static P) -> Self {
        PwmMuxComponent { pwm }
    }
}

impl<P: 'static + pwm::Pwm> Component for PwmMuxComponent<P> {
    type StaticInput = &'static mut MaybeUninit<MuxPwm<'static, P>>;
    type Output = &'static MuxPwm<'static, P>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let pwm_mux = static_buffer.write(MuxPwm::new(self.pwm));

        pwm_mux
    }
}

pub struct PwmPinUserComponent<P: 'static + pwm::Pwm> {
    pwm_mux: &'static MuxPwm<'static, P>,
    channel: P::Pin,
}

impl<P: 'static + pwm::Pwm> PwmPinUserComponent<P> {
    pub fn new(mux: &'static MuxPwm<'static, P>, channel: P::Pin) -> Self {
        PwmPinUserComponent {
            pwm_mux: mux,
            channel,
        }
    }
}

impl<P: 'static + pwm::Pwm> Component for PwmPinUserComponent<P> {
    type StaticInput = &'static mut MaybeUninit<PwmPinUser<'static, P>>;
    type Output = &'static PwmPinUser<'static, P>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let pwm_pin = static_buffer.write(PwmPinUser::new(self.pwm_mux, self.channel));

        pwm_pin.add_to_mux();

        pwm_pin
    }
}

pub struct PwmDriverComponent<const NUM_PINS: usize> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
}

impl<const NUM_PINS: usize> PwmDriverComponent<NUM_PINS> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
    ) -> PwmDriverComponent<NUM_PINS> {
        PwmDriverComponent {
            board_kernel,
            driver_num,
        }
    }
}

impl<const NUM_PINS: usize> Component for PwmDriverComponent<NUM_PINS> {
    type StaticInput = (
        &'static mut MaybeUninit<Pwm<'static, NUM_PINS>>,
        &'static [&'static dyn kernel::hil::pwm::PwmPin; NUM_PINS],
    );
    type Output = &'static capsules_extra::pwm::Pwm<'static, NUM_PINS>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let grant_adc = self.board_kernel.create_grant(self.driver_num, &grant_cap);

        let pwm = static_buffer
            .0
            .write(capsules_extra::pwm::Pwm::new(static_buffer.1, grant_adc));

        pwm
    }
}
