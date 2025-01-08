// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! General Purpose Input/Output (GPIO)

use core::cell::Cell;
use core::marker::PhantomData;
use kernel::hil::gpio;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::registers::{register_bitfields, register_structs, ReadOnly, ReadWrite};
use kernel::utilities::StaticRef;

const GPIO_BASES: [StaticRef<GpioRegisters>; 6] = [
    unsafe { StaticRef::new(0x4000_4C00u32 as *const GpioRegisters) }, // PORT 1&2
    unsafe { StaticRef::new(0x4000_4C20u32 as *const GpioRegisters) }, // PORT 3&4
    unsafe { StaticRef::new(0x4000_4C40u32 as *const GpioRegisters) }, // PORT 5&6
    unsafe { StaticRef::new(0x4000_4C60u32 as *const GpioRegisters) }, // PORT 7&8
    unsafe { StaticRef::new(0x4000_4C80u32 as *const GpioRegisters) }, // PORT 9&10
    unsafe { StaticRef::new(0x4000_4D20u32 as *const GpioRegisters) }, // PORT J
];

const PINS_PER_PORT: u8 = 8;

register_structs! {
    GpioRegisters {
        (0x00 => input: [ReadOnly<u8, PxIN::Register>; 2]),
        (0x02 => out: [ReadWrite<u8, PxOUT::Register>; 2]),
        (0x04 => dir: [ReadWrite<u8, PxDIR::Register>; 2]),
        (0x06 => ren: [ReadWrite<u8, PxREN::Register>; 2]),
        (0x08 => ds: [ReadWrite<u8, PxDS::Register>; 2]),
        (0x0A => sel0: [ReadWrite<u8, PxSEL0::Register>; 2]),
        (0x0C => sel1: [ReadWrite<u8, PxSEL1::Register>; 2]),
        (0x0E => iv1: ReadWrite<u16, PxIV::Register>),
        (0x10 => _reserved),
        (0x16 => selc: [ReadWrite<u8, PxSELC::Register>; 2]),
        (0x18 => ies: [ReadWrite<u8, PxIES::Register>; 2]),
        (0x1A => ie: [ReadWrite<u8, PxIE::Register>; 2]),
        (0x1C => ifg: [ReadWrite<u8, PxIFG::Register>; 2]),
        (0x1E => iv2: ReadWrite<u16, PxIV::Register>),
        (0x20 => @END),
    }
}

register_bitfields! [u8,
    /// Input-register, get input-status of pins
    PxIN [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Output-register, set output status of pins
    PxOUT [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Direction-register, set direction of pins
    PxDIR [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Pull-register, enable/disable pullup- or -down resistor
    PxREN [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Drive-strength register, select high(1) or low(0) drive-strength
    PxDS [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Function-selection register 0, combined with function-selection 1 the
    /// module function is selected (GPIO, primary, secondary or tertiary)
    PxSEL0 [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Function-selection register 1, combined with function-selection 0 the
    /// module function is selected (GPIO, primary, secondary or tertiary)
    PxSEL1 [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Complement selection, set a bit in PxSEL0 and PxSEL1 concurrently
    PxSELC [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Interrupt-edge selction, 0=rising-edge, 1=falling-edge
    PxIES [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Interrupt enable register
    PxIE [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ],
    /// Interrupt flag register
    PxIFG [
        PIN0 OFFSET(0) NUMBITS(1),
        PIN1 OFFSET(1) NUMBITS(1),
        PIN2 OFFSET(2) NUMBITS(1),
        PIN3 OFFSET(3) NUMBITS(1),
        PIN4 OFFSET(4) NUMBITS(1),
        PIN5 OFFSET(5) NUMBITS(1),
        PIN6 OFFSET(6) NUMBITS(1),
        PIN7 OFFSET(7) NUMBITS(1)
    ]
];

register_bitfields! [u16,
    // interrupt vector register
    PxIV [
        IV OFFSET(0) NUMBITS(16)
    ]
];

#[rustfmt::skip]
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum IntPinNr {
    P01_0, P01_1, P01_2, P01_3, P01_4, P01_5, P01_6, P01_7,
    P02_0, P02_1, P02_2, P02_3, P02_4, P02_5, P02_6, P02_7,
    P03_0, P03_1, P03_2, P03_3, P03_4, P03_5, P03_6, P03_7,
    P04_0, P04_1, P04_2, P04_3, P04_4, P04_5, P04_6, P04_7,
    P05_0, P05_1, P05_2, P05_3, P05_4, P05_5, P05_6, P05_7,
    P06_0, P06_1, P06_2, P06_3, P06_4, P06_5, P06_6, P06_7,
}

#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum PinNr {
    P07_0, P07_1, P07_2, P07_3, P07_4, P07_5, P07_6, P07_7,
    P08_0, P08_1, P08_2, P08_3, P08_4, P08_5, P08_6, P08_7,
    P09_0, P09_1, P09_2, P09_3, P09_4, P09_5, P09_6, P09_7,
    P10_0, P10_1, P10_2, P10_3, P10_4, P10_5, P10_6, P10_7,
    PJ_0,  PJ_1,  PJ_2,  PJ_3,  PJ_4,  PJ_5,  PJ_6,  PJ_7,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ModuleFunction {
    Gpio,
    Primary,
    Secondary,
    Tertiary,
}

pub struct GpioManager<'a> {
    pub int_pins: [IntPin<'a>; 48],
    pub pins: [Pin<'a>; 40],
}

impl GpioManager<'_> {
    pub fn new() -> Self {
        Self {
            int_pins: [
                IntPin::new(IntPinNr::P01_0),
                IntPin::new(IntPinNr::P01_1),
                IntPin::new(IntPinNr::P01_2),
                IntPin::new(IntPinNr::P01_3),
                IntPin::new(IntPinNr::P01_4),
                IntPin::new(IntPinNr::P01_5),
                IntPin::new(IntPinNr::P01_6),
                IntPin::new(IntPinNr::P01_7),
                IntPin::new(IntPinNr::P02_0),
                IntPin::new(IntPinNr::P02_1),
                IntPin::new(IntPinNr::P02_2),
                IntPin::new(IntPinNr::P02_3),
                IntPin::new(IntPinNr::P02_4),
                IntPin::new(IntPinNr::P02_5),
                IntPin::new(IntPinNr::P02_6),
                IntPin::new(IntPinNr::P02_7),
                IntPin::new(IntPinNr::P03_0),
                IntPin::new(IntPinNr::P03_1),
                IntPin::new(IntPinNr::P03_2),
                IntPin::new(IntPinNr::P03_3),
                IntPin::new(IntPinNr::P03_4),
                IntPin::new(IntPinNr::P03_5),
                IntPin::new(IntPinNr::P03_6),
                IntPin::new(IntPinNr::P03_7),
                IntPin::new(IntPinNr::P04_0),
                IntPin::new(IntPinNr::P04_1),
                IntPin::new(IntPinNr::P04_2),
                IntPin::new(IntPinNr::P04_3),
                IntPin::new(IntPinNr::P04_4),
                IntPin::new(IntPinNr::P04_5),
                IntPin::new(IntPinNr::P04_6),
                IntPin::new(IntPinNr::P04_7),
                IntPin::new(IntPinNr::P05_0),
                IntPin::new(IntPinNr::P05_1),
                IntPin::new(IntPinNr::P05_2),
                IntPin::new(IntPinNr::P05_3),
                IntPin::new(IntPinNr::P05_4),
                IntPin::new(IntPinNr::P05_5),
                IntPin::new(IntPinNr::P05_6),
                IntPin::new(IntPinNr::P05_7),
                IntPin::new(IntPinNr::P06_0),
                IntPin::new(IntPinNr::P06_1),
                IntPin::new(IntPinNr::P06_2),
                IntPin::new(IntPinNr::P06_3),
                IntPin::new(IntPinNr::P06_4),
                IntPin::new(IntPinNr::P06_5),
                IntPin::new(IntPinNr::P06_6),
                IntPin::new(IntPinNr::P06_7),
            ],
            pins: [
                Pin::new(PinNr::P07_0),
                Pin::new(PinNr::P07_1),
                Pin::new(PinNr::P07_2),
                Pin::new(PinNr::P07_3),
                Pin::new(PinNr::P07_4),
                Pin::new(PinNr::P07_5),
                Pin::new(PinNr::P07_6),
                Pin::new(PinNr::P07_7),
                Pin::new(PinNr::P08_0),
                Pin::new(PinNr::P08_1),
                Pin::new(PinNr::P08_2),
                Pin::new(PinNr::P08_3),
                Pin::new(PinNr::P08_4),
                Pin::new(PinNr::P08_5),
                Pin::new(PinNr::P08_6),
                Pin::new(PinNr::P08_7),
                Pin::new(PinNr::P09_0),
                Pin::new(PinNr::P09_1),
                Pin::new(PinNr::P09_2),
                Pin::new(PinNr::P09_3),
                Pin::new(PinNr::P09_4),
                Pin::new(PinNr::P09_5),
                Pin::new(PinNr::P09_6),
                Pin::new(PinNr::P09_7),
                Pin::new(PinNr::P10_0),
                Pin::new(PinNr::P10_1),
                Pin::new(PinNr::P10_2),
                Pin::new(PinNr::P10_3),
                Pin::new(PinNr::P10_4),
                Pin::new(PinNr::P10_5),
                Pin::new(PinNr::P10_6),
                Pin::new(PinNr::P10_7),
                Pin::new(PinNr::PJ_0),
                Pin::new(PinNr::PJ_1),
                Pin::new(PinNr::PJ_2),
                Pin::new(PinNr::PJ_3),
                Pin::new(PinNr::PJ_4),
                Pin::new(PinNr::PJ_5),
                Pin::new(PinNr::PJ_6),
                Pin::new(PinNr::PJ_7),
            ],
        }
    }
}

/// Supports interrupts
pub struct IntPin<'a> {
    pin: u8,
    registers: StaticRef<GpioRegisters>,
    reg_idx: usize,
    detect_both_edges: Cell<bool>,
    client: OptionalCell<&'a dyn gpio::Client>,
}

/// Does not support interrupts
pub struct Pin<'a> {
    pin: u8,
    registers: StaticRef<GpioRegisters>,
    reg_idx: usize,
    // Add the phantom data in order to make the macro implementation work
    // because IntPin requires a lifetime parameter
    phantom: PhantomData<&'a ()>,
}

impl<'a> Pin<'a> {
    const fn new(pin: PinNr) -> Pin<'a> {
        let pin_nr = (pin as u8) % PINS_PER_PORT;
        let p = (pin as u8) / PINS_PER_PORT;
        Pin {
            pin: pin_nr,
            registers: GPIO_BASES[3 + ((p / 2) as usize)],
            reg_idx: (p % 2) as usize,
            phantom: PhantomData,
        }
    }
}

impl<'a> IntPin<'a> {
    pub const fn new(pin: IntPinNr) -> IntPin<'a> {
        let pin_nr = (pin as u8) % PINS_PER_PORT;
        let p = (pin as u8) / PINS_PER_PORT;
        IntPin {
            pin: pin_nr,
            registers: GPIO_BASES[(p / 2) as usize],
            reg_idx: (p % 2) as usize,
            detect_both_edges: Cell::new(false),
            client: OptionalCell::empty(),
        }
    }

    fn switch_detecting_edge(&self) {
        // Don't rely on the current configuration of the edge-detection, read the current state
        // of the pin and set the detecting edge based on this information. It could be that we
        // already missed one or more interrupts, so it doesn't make sense to just switch the edge.

        let mut edge = self.registers.ies[self.reg_idx].get();
        if self.read_level() {
            // Pin is high -> detect falling edge
            edge |= 1 << self.pin;
        } else {
            // Pin is low -> detect rising edge
            edge &= !(1 << self.pin);
        }
        self.registers.ies[self.reg_idx].set(edge);
    }

    fn handle_interrupt(&self) {
        self.client.map(|client| client.fired());

        if self.detect_both_edges.get() {
            self.switch_detecting_edge();
        }
    }
}

macro_rules! pin_implementation {
    ($pin_type:ident) => {
        impl<'a> $pin_type<'a> {
            fn read_level(&self) -> bool {
                (self.registers.input[self.reg_idx].get() & (1 << self.pin)) > 0
            }

            fn enable_module_function(&self, mode: ModuleFunction) {
                let mut sel0 = self.registers.sel0[self.reg_idx].get();
                let mut sel1 = self.registers.sel1[self.reg_idx].get();

                match mode {
                    ModuleFunction::Gpio => {
                        sel0 &= !(1 << self.pin);
                        sel1 &= !(1 << self.pin);
                    }
                    ModuleFunction::Primary => {
                        sel0 |= 1 << self.pin;
                        sel1 &= !(1 << self.pin);
                    }
                    ModuleFunction::Secondary => {
                        sel0 &= !(1 << self.pin);
                        sel1 |= 1 << self.pin;
                    }
                    ModuleFunction::Tertiary => {
                        sel0 |= 1 << self.pin;
                        sel1 |= 1 << self.pin;
                    }
                }

                self.registers.sel0[self.reg_idx].set(sel0);
                self.registers.sel1[self.reg_idx].set(sel1);
            }

            pub fn enable_primary_function(&self) {
                self.enable_module_function(ModuleFunction::Primary);
            }

            pub fn enable_secondary_function(&self) {
                self.enable_module_function(ModuleFunction::Secondary);
            }

            pub fn enable_tertiary_function(&self) {
                self.enable_module_function(ModuleFunction::Tertiary);
            }
        }

        impl<'a> gpio::Input for $pin_type<'a> {
            fn read(&self) -> bool {
                self.read_level()
            }
        }

        impl<'a> gpio::Output for $pin_type<'a> {
            fn set(&self) {
                let mut val = self.registers.out[self.reg_idx].get();
                val |= 1 << self.pin;
                self.registers.out[self.reg_idx].set(val);
            }

            fn clear(&self) {
                let mut val = self.registers.out[self.reg_idx].get();
                val &= !(1 << self.pin);
                self.registers.out[self.reg_idx].set(val);
            }

            fn toggle(&self) -> bool {
                let mut val = self.registers.out[self.reg_idx].get();
                val ^= 1 << self.pin;
                self.registers.out[self.reg_idx].set(val);
                (val & (1 << self.pin)) > 0
            }
        }

        impl<'a> gpio::Configure for $pin_type<'a> {
            fn configuration(&self) -> gpio::Configuration {
                let regs = self.registers;
                let dir = regs.dir[self.reg_idx].get();
                let mut sel = ((regs.sel0[self.reg_idx].get() & (1 << self.pin)) > 0) as u8;
                sel |= (((regs.sel1[self.reg_idx].get() & (1 << self.pin)) > 0) as u8) << 1;

                if sel > 0 {
                    gpio::Configuration::Function
                } else {
                    if (dir & (1 << self.pin)) > 0 {
                        gpio::Configuration::Output
                    } else {
                        gpio::Configuration::Input
                    }
                }
            }

            fn make_output(&self) -> gpio::Configuration {
                use gpio::Output;
                self.enable_module_function(ModuleFunction::Gpio);

                let mut val = self.registers.dir[self.reg_idx].get();
                val |= 1 << self.pin;
                self.registers.dir[self.reg_idx].set(val);

                // Clear the output since the state of an output is undefined after a reset
                self.clear();
                gpio::Configuration::Output
            }

            fn disable_output(&self) -> gpio::Configuration {
                self.make_input()
            }

            fn make_input(&self) -> gpio::Configuration {
                self.enable_module_function(ModuleFunction::Gpio);

                let mut val = self.registers.dir[self.reg_idx].get();
                val &= !(1 << self.pin);
                self.registers.dir[self.reg_idx].set(val);
                gpio::Configuration::Input
            }

            fn disable_input(&self) -> gpio::Configuration {
                // it's not possible to deactivate the pin at all, so just return the
                // current configuration
                self.configuration()
            }

            fn deactivate_to_low_power(&self) {
                // the chip doesn't support any low-power, so set it to input with
                // a pullup resistor which should not consume much current
                self.make_input();
                self.set_floating_state(gpio::FloatingState::PullUp);
            }

            fn set_floating_state(&self, state: gpio::FloatingState) {
                let regs = self.registers;
                let mut ren = regs.ren[self.reg_idx].get();
                let mut out = regs.out[self.reg_idx].get();
                match state {
                    gpio::FloatingState::PullDown => {
                        ren |= 1 << self.pin;
                        out &= !(1 << self.pin);
                    }
                    gpio::FloatingState::PullUp => {
                        ren |= 1 << self.pin;
                        out |= 1 << self.pin;
                    }
                    gpio::FloatingState::PullNone => {
                        ren &= !(1 << self.pin);
                    }
                }
                regs.ren[self.reg_idx].set(ren);
                regs.out[self.reg_idx].set(out);
            }

            fn floating_state(&self) -> gpio::FloatingState {
                let ren = self.registers.ren[self.reg_idx].get();
                let out = self.registers.out[self.reg_idx].get();

                if (ren & (1 << self.pin)) > 0 {
                    if (out & (1 << self.pin)) > 0 {
                        gpio::FloatingState::PullUp
                    } else {
                        gpio::FloatingState::PullDown
                    }
                } else {
                    gpio::FloatingState::PullNone
                }
            }
        }
    };
}

pin_implementation!(IntPin);
pin_implementation!(Pin);

impl<'a> gpio::Interrupt<'a> for IntPin<'a> {
    fn set_client(&self, client: &'a dyn gpio::Client) {
        self.client.set(client);
    }

    fn enable_interrupts(&self, mode: gpio::InterruptEdge) {
        // disable the interrupt at the beginning because modifying the edge-select register
        // could trigger an interrupt -> datasheet p. 680 section 12.2.7.1
        self.disable_interrupts();

        let mut edge = self.registers.ies[self.reg_idx].get();
        match mode {
            gpio::InterruptEdge::FallingEdge => {
                self.detect_both_edges.set(false);
                edge |= 1 << self.pin;
            }
            gpio::InterruptEdge::RisingEdge => {
                self.detect_both_edges.set(false);
                edge &= !(1 << self.pin);
            }
            gpio::InterruptEdge::EitherEdge => {
                // Implement a software based implementation for detecting both edges since
                // this controller doesn't support this feature by hardware
                self.detect_both_edges.set(true);
                if self.read_level() {
                    // If the pin-level is high, configure for falling edges.
                    edge |= 1 << self.pin;
                } else {
                    // If the pin-level is low, configure for rising edges.
                    edge &= !(1 << self.pin);
                }
            }
        }

        // Set the edge detection
        self.registers.ies[self.reg_idx].set(edge);
        // Clear eventually caused interrupts
        self.registers.ifg[self.reg_idx]
            .set(self.registers.ifg[self.reg_idx].get() & !(1 << self.pin));
        // Enable the interrupt
        self.registers.ie[self.reg_idx]
            .set(self.registers.ie[self.reg_idx].get() | (1 << self.pin));
    }

    fn disable_interrupts(&self) {
        let mut enable = self.registers.ie[self.reg_idx].get();
        enable &= !(1 << self.pin);
        self.registers.ie[self.reg_idx].set(enable);
    }

    fn is_pending(&self) -> bool {
        (self.registers.ifg[self.reg_idx].get() & (1 << self.pin)) > 0
    }
}

impl GpioManager<'_> {
    pub fn handle_interrupt(&self, port_idx: usize) {
        let regs: StaticRef<GpioRegisters> = GPIO_BASES[port_idx / 2];
        let ifgs: [u8; 2] = [regs.ifg[0].get(), regs.ifg[1].get()];

        let handle_int = |ifg_idx: usize, i: usize| {
            let bit = 1 << i;
            if (ifgs[ifg_idx] & bit) > 0 {
                self.int_pins[(port_idx * 8) + i].handle_interrupt();
                // read back the current register value to avoid loosing interrupts which occured
                // within this function
                regs.ifg[ifg_idx].set(regs.ifg[ifg_idx].get() & !bit);
            }
        };

        for i in 0..8 {
            handle_int(0, i);
            handle_int(1, i);
        }
    }
}
