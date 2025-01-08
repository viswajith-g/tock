// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! GPIO instantiation.

use core::ops::{Index, IndexMut};

use kernel::utilities::StaticRef;
use sifive::gpio::{pins, GpioPin, GpioRegisters};

pub const GPIO0_BASE: StaticRef<GpioRegisters> =
    unsafe { StaticRef::new(0x1001_2000 as *const GpioRegisters) };

pub struct Port<'a> {
    pins: [GpioPin<'a>; 32],
}

impl<'a> Index<usize> for Port<'a> {
    type Output = GpioPin<'a>;

    fn index(&self, index: usize) -> &GpioPin<'a> {
        &self.pins[index]
    }
}

impl<'a> IndexMut<usize> for Port<'a> {
    fn index_mut(&mut self, index: usize) -> &mut GpioPin<'a> {
        &mut self.pins[index]
    }
}

impl Port<'_> {
    pub const fn new() -> Self {
        Self {
            pins: [
                GpioPin::new(GPIO0_BASE, pins::pin0, pins::pin0::SET, pins::pin0::CLEAR),
                GpioPin::new(GPIO0_BASE, pins::pin1, pins::pin1::SET, pins::pin1::CLEAR),
                GpioPin::new(GPIO0_BASE, pins::pin2, pins::pin2::SET, pins::pin2::CLEAR),
                GpioPin::new(GPIO0_BASE, pins::pin3, pins::pin3::SET, pins::pin3::CLEAR),
                GpioPin::new(GPIO0_BASE, pins::pin4, pins::pin4::SET, pins::pin4::CLEAR),
                GpioPin::new(GPIO0_BASE, pins::pin5, pins::pin5::SET, pins::pin5::CLEAR),
                GpioPin::new(GPIO0_BASE, pins::pin6, pins::pin6::SET, pins::pin6::CLEAR),
                GpioPin::new(GPIO0_BASE, pins::pin7, pins::pin7::SET, pins::pin7::CLEAR),
                GpioPin::new(GPIO0_BASE, pins::pin8, pins::pin8::SET, pins::pin8::CLEAR),
                GpioPin::new(GPIO0_BASE, pins::pin9, pins::pin9::SET, pins::pin9::CLEAR),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin10,
                    pins::pin10::SET,
                    pins::pin10::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin11,
                    pins::pin11::SET,
                    pins::pin11::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin12,
                    pins::pin12::SET,
                    pins::pin12::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin13,
                    pins::pin13::SET,
                    pins::pin13::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin14,
                    pins::pin14::SET,
                    pins::pin14::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin15,
                    pins::pin15::SET,
                    pins::pin15::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin16,
                    pins::pin16::SET,
                    pins::pin16::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin17,
                    pins::pin17::SET,
                    pins::pin17::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin18,
                    pins::pin18::SET,
                    pins::pin18::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin19,
                    pins::pin19::SET,
                    pins::pin19::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin20,
                    pins::pin20::SET,
                    pins::pin20::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin21,
                    pins::pin21::SET,
                    pins::pin21::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin22,
                    pins::pin22::SET,
                    pins::pin22::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin23,
                    pins::pin23::SET,
                    pins::pin23::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin24,
                    pins::pin24::SET,
                    pins::pin24::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin25,
                    pins::pin25::SET,
                    pins::pin25::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin26,
                    pins::pin26::SET,
                    pins::pin26::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin27,
                    pins::pin27::SET,
                    pins::pin27::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin28,
                    pins::pin28::SET,
                    pins::pin28::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin29,
                    pins::pin29::SET,
                    pins::pin29::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin30,
                    pins::pin30::SET,
                    pins::pin30::CLEAR,
                ),
                GpioPin::new(
                    GPIO0_BASE,
                    pins::pin31,
                    pins::pin31::SET,
                    pins::pin31::CLEAR,
                ),
            ],
        }
    }
}
