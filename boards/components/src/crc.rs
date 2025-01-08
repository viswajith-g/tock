// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Component for Crc syscall interface.
//!
//! This provides one Component, `CrcComponent`, which implements a
//! userspace syscall interface to the Crc peripheral.
//!
//! Usage
//! -----
//! ```rust
//! let crc = components::crc::CrcComponent::new(board_kernel, &sam4l::crccu::CrcCU)
//!     .finalize(components::crc_component_static!(sam4l::crccu::Crccu));
//! ```

// Author: Philip Levis <pal@cs.stanford.edu>
// Author: Leon Schuermann  <leon@is.currently.online>
// Last modified: 6/2/2021

use capsules_extra::crc::CrcDriver;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil::crc::Crc;

// Setup static space for the objects.
#[macro_export]
macro_rules! crc_component_static {
    ($C:ty $(,)?) => {{
        let buffer = kernel::static_buf!([u8; capsules_extra::crc::DEFAULT_CRC_BUF_LENGTH]);
        let crc = kernel::static_buf!(capsules_extra::crc::CrcDriver<'static, $C>);

        (crc, buffer)
    };};
}

pub struct CrcComponent<C: 'static + Crc<'static>> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    crc: &'static C,
}

impl<C: 'static + Crc<'static>> CrcComponent<C> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        crc: &'static C,
    ) -> CrcComponent<C> {
        CrcComponent {
            board_kernel,
            driver_num,
            crc,
        }
    }
}

impl<C: 'static + Crc<'static>> Component for CrcComponent<C> {
    type StaticInput = (
        &'static mut MaybeUninit<CrcDriver<'static, C>>,
        &'static mut MaybeUninit<[u8; capsules_extra::crc::DEFAULT_CRC_BUF_LENGTH]>,
    );
    type Output = &'static CrcDriver<'static, C>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let crc_buf = static_buffer
            .1
            .write([0; capsules_extra::crc::DEFAULT_CRC_BUF_LENGTH]);

        let crc = static_buffer.0.write(CrcDriver::new(
            self.crc,
            crc_buf,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
        ));

        self.crc.set_client(crc);

        crc
    }
}
