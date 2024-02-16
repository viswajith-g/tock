// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Components for the L3GD20 sensor.
//!
//! Uses a SPI Interface.
//!
//! Usage
//! -----
//! ```rust
//! let l3gd20 = components::l3gd20::L3gd20Component::new(spi_mux, stm32f429zi::gpio::PinId::PE03).finalize(
//!     components::l3gd20_component_static!(stm32f429zi::spi::Spi));
//! ```

use capsules_core::virtualizers::virtual_spi::{MuxSpiMaster, VirtualSpiMasterDevice};
use capsules_extra::l3gd20::L3gd20Spi;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil::spi;
use kernel::hil::spi::SpiMasterDevice;

// Setup static space for the objects.
#[macro_export]
macro_rules! l3gd20_component_static {
    ($S:ty $(,)?) => {{
        let txbuffer = kernel::static_buf!([u8; capsules_extra::l3gd20::TX_BUF_LEN]);
        let rxbuffer = kernel::static_buf!([u8; capsules_extra::l3gd20::RX_BUF_LEN]);

        let spi = kernel::static_buf!(
            capsules_core::virtualizers::virtual_spi::VirtualSpiMasterDevice<'static, $S>
        );
        let l3gd20spi = kernel::static_buf!(
            capsules_extra::l3gd20::L3gd20Spi<
                'static,
                capsules_core::virtualizers::virtual_spi::VirtualSpiMasterDevice<'static, $S>,
            >
        );

        (spi, l3gd20spi, txbuffer, rxbuffer)
    };};
}

pub type L3gd20ComponentType<S> = capsules_extra::l3gd20::L3gd20Spi<'static, S>;

pub struct L3gd20Component<S: 'static + spi::SpiMaster<'static>> {
    spi_mux: &'static MuxSpiMaster<'static, S>,
    chip_select: S::ChipSelect,
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
}

impl<S: 'static + spi::SpiMaster<'static>> L3gd20Component<S> {
    pub fn new(
        spi_mux: &'static MuxSpiMaster<'static, S>,
        chip_select: S::ChipSelect,
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
    ) -> L3gd20Component<S> {
        L3gd20Component {
            spi_mux,
            chip_select,
            board_kernel,
            driver_num,
        }
    }
}

impl<S: 'static + spi::SpiMaster<'static>> Component for L3gd20Component<S> {
    type StaticInput = (
        &'static mut MaybeUninit<VirtualSpiMasterDevice<'static, S>>,
        &'static mut MaybeUninit<L3gd20Spi<'static, VirtualSpiMasterDevice<'static, S>>>,
        &'static mut MaybeUninit<[u8; capsules_extra::l3gd20::TX_BUF_LEN]>,
        &'static mut MaybeUninit<[u8; capsules_extra::l3gd20::RX_BUF_LEN]>,
    );
    type Output = &'static L3gd20Spi<'static, VirtualSpiMasterDevice<'static, S>>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let grant = self.board_kernel.create_grant(self.driver_num, &grant_cap);

        let spi_device = static_buffer
            .0
            .write(VirtualSpiMasterDevice::new(self.spi_mux, self.chip_select));
        spi_device.setup();

        let txbuffer = static_buffer
            .2
            .write([0; capsules_extra::l3gd20::TX_BUF_LEN]);
        let rxbuffer = static_buffer
            .3
            .write([0; capsules_extra::l3gd20::RX_BUF_LEN]);

        let l3gd20 = static_buffer
            .1
            .write(L3gd20Spi::new(spi_device, txbuffer, rxbuffer, grant));
        spi_device.set_client(l3gd20);

        // TODO verify SPI return value
        let _ = l3gd20.configure();

        l3gd20
    }
}
