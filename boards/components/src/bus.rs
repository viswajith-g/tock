// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Bus Components for Intel8080 Parallel Interface, I2C, SPI
//!
//! Example
//!
//! Intel 8080 Parallel Interface
//!
//! let bus = components::bus::Bus8080BusComponent::new(&stm32f412g::fsmc::FSMC).finalize(
//!     components::bus8080_bus_component_static!(stm32f412g::fsmc::Fsmc)
//! );
//!
//! SPI
//!
//! ```rust
//! let bus = components::bus::SpiMasterBusComponent::new(spi_mux,
//!                                                       chip_select,
//!                                                       baud_rate,
//!                                                       clock_phase,
//!                                                       clock_polarity).finalize(
//!     components::spi_bus_component_static!(nrf52840::spi::SPIM)
//! );
//! ```

use capsules_core::virtualizers::virtual_i2c::{I2CDevice, MuxI2C};
use capsules_core::virtualizers::virtual_spi::MuxSpiMaster;
use capsules_core::virtualizers::virtual_spi::VirtualSpiMasterDevice;
use capsules_extra::bus::{Bus8080Bus, I2CMasterBus, SpiMasterBus};
use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::hil::bus8080;
use kernel::hil::i2c;
use kernel::hil::spi::{self, ClockPhase, ClockPolarity, SpiMasterDevice};

// Setup static space for the objects.
#[macro_export]
macro_rules! bus8080_bus_component_static {
    ($B:ty $(,)?) => {{
        kernel::static_buf!(capsules_extra::bus::Bus8080Bus<'static, $B>)
    };};
}

#[macro_export]
macro_rules! spi_bus_component_static {
    ($S:ty $(,)?) => {{
        let spi = kernel::static_buf!(
            capsules_core::virtualizers::virtual_spi::VirtualSpiMasterDevice<'static, $S>
        );
        let address_buffer = kernel::static_buf!([u8; core::mem::size_of::<usize>()]);
        let bus = kernel::static_buf!(
            capsules_extra::bus::SpiMasterBus<
                'static,
                capsules_core::virtualizers::virtual_spi::VirtualSpiMasterDevice<'static, $S>,
            >
        );

        (spi, bus, address_buffer)
    };};
}

#[macro_export]
macro_rules! i2c_master_bus_component_static {
    ($D:ty $(,)?) => {{
        let address_buffer = kernel::static_buf!([u8; 1]);
        let bus = kernel::static_buf!(capsules_extra::bus::I2CMasterBus<'static, $D>);
        let i2c_device = kernel::static_buf!(
            capsules_core::virtualizers::virtual_i2c::I2CDevice<
                'static,
                capsules_extra::bus::I2CMasterBus<'static, $D>,
            >
        );

        (bus, i2c_device, address_buffer)
    };};
}

pub struct Bus8080BusComponent<B: 'static + bus8080::Bus8080<'static>> {
    bus: &'static B,
}

impl<B: 'static + bus8080::Bus8080<'static>> Bus8080BusComponent<B> {
    pub fn new(bus: &'static B) -> Bus8080BusComponent<B> {
        Bus8080BusComponent { bus }
    }
}

impl<B: 'static + bus8080::Bus8080<'static>> Component for Bus8080BusComponent<B> {
    type StaticInput = &'static mut MaybeUninit<Bus8080Bus<'static, B>>;
    type Output = &'static Bus8080Bus<'static, B>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let bus = static_buffer.write(Bus8080Bus::new(self.bus));
        self.bus.set_client(bus);

        bus
    }
}

pub struct SpiMasterBusComponent<S: 'static + spi::SpiMaster<'static>> {
    spi_mux: &'static MuxSpiMaster<'static, S>,
    chip_select: S::ChipSelect,
    baud_rate: u32,
    clock_phase: ClockPhase,
    clock_polarity: ClockPolarity,
}

impl<S: 'static + spi::SpiMaster<'static>> SpiMasterBusComponent<S> {
    pub fn new(
        spi_mux: &'static MuxSpiMaster<'static, S>,
        chip_select: S::ChipSelect,
        baud_rate: u32,
        clock_phase: ClockPhase,
        clock_polarity: ClockPolarity,
    ) -> SpiMasterBusComponent<S> {
        SpiMasterBusComponent {
            spi_mux,
            chip_select,
            baud_rate,
            clock_phase,
            clock_polarity,
        }
    }
}

impl<S: 'static + spi::SpiMaster<'static>> Component for SpiMasterBusComponent<S> {
    type StaticInput = (
        &'static mut MaybeUninit<VirtualSpiMasterDevice<'static, S>>,
        &'static mut MaybeUninit<SpiMasterBus<'static, VirtualSpiMasterDevice<'static, S>>>,
        &'static mut MaybeUninit<[u8; core::mem::size_of::<usize>()]>,
    );
    type Output = &'static SpiMasterBus<'static, VirtualSpiMasterDevice<'static, S>>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let spi_device = static_buffer
            .0
            .write(VirtualSpiMasterDevice::new(self.spi_mux, self.chip_select));
        spi_device.setup();

        if let Err(error) =
            spi_device.configure(self.clock_polarity, self.clock_phase, self.baud_rate)
        {
            panic!("Failed to setup SPI Bus ({:?})", error);
        }

        let buffer = static_buffer.2.write([0; core::mem::size_of::<usize>()]);

        let bus = static_buffer.1.write(SpiMasterBus::new(spi_device, buffer));
        spi_device.set_client(bus);

        bus
    }
}

pub struct I2CMasterBusComponent<I: 'static + i2c::I2CMaster<'static>> {
    i2c_mux: &'static MuxI2C<'static, I>,
    address: u8,
}

impl<I: 'static + i2c::I2CMaster<'static>> I2CMasterBusComponent<I> {
    pub fn new(i2c_mux: &'static MuxI2C<'static, I>, address: u8) -> I2CMasterBusComponent<I> {
        I2CMasterBusComponent { i2c_mux, address }
    }
}

impl<I: 'static + i2c::I2CMaster<'static>> Component for I2CMasterBusComponent<I> {
    type StaticInput = (
        &'static mut MaybeUninit<I2CMasterBus<'static, I2CDevice<'static, I>>>,
        &'static mut MaybeUninit<I2CDevice<'static, I>>,
        &'static mut MaybeUninit<[u8; 1]>,
    );
    type Output = &'static I2CMasterBus<'static, I2CDevice<'static, I>>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let i2c_device = static_buffer
            .1
            .write(I2CDevice::new(self.i2c_mux, self.address));
        let buffer = static_buffer.2.write([0; 1]);

        let bus = static_buffer.0.write(I2CMasterBus::new(i2c_device, buffer));
        i2c_device.set_client(bus);

        bus
    }
}
