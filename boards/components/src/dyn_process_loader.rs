// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Component for non-volatile storage Drivers.
//!
//! This provides one component, NonvolatileStorageComponent, which provides
//! a system call interface to non-volatile storage.
//!
//! Usage
//! -----
//! ```rust
//! let nonvolatile_storage = components::nonvolatile_storage::NonvolatileStorageComponent::new(
//!     board_kernel,
//!     &sam4l::flashcalw::FLASH_CONTROLLER,
//!     0x60000,
//!     0x20000,
//!     &_sstorage as *const u8 as usize,
//!     &_estorage as *const u8 as usize,
//! )
//! .finalize(components::nonvolatile_storage_component_static!(
//!     sam4l::flashcalw::FLASHCALW
//! ));
//! ```

use kernel::process_load_utilities::DynamicProcessLoader;
use capsules_extra::nonvolatile_to_pages::NonvolatileToPages;
use core::mem::MaybeUninit;
// use kernel::capabilities;
use kernel::component::Component;
// use kernel::create_capability;
use kernel::hil;
use kernel::process;
use kernel::process::ProcessFaultPolicy;
use kernel::platform::chip::Chip;

// Setup static space for the objects.
#[macro_export]
macro_rules! process_loader_component_static {
    ($F:ty, $C:ty $(,)?) => {{
        let page = kernel::static_buf!(<$F as kernel::hil::flash::Flash>::Page);
        let ntp = kernel::static_buf!(
            capsules_extra::nonvolatile_to_pages::NonvolatileToPages<'static, $F>
        );
        let pl = kernel::static_buf!(
            kernel::process_load_utilities::DynamicProcessLoader<$C>
        );
        let buffer = kernel::static_buf!([u8; kernel::process_load_utilities::BUF_LEN]);

        (page, ntp, pl, buffer)
    };};
}

pub struct ProcessLoaderComponent<
    F: 'static + hil::flash::Flash + hil::flash::HasClient<'static, NonvolatileToPages<'static, F>>, C: 'static + Chip,
> {
    processes: &'static mut [Option<&'static dyn process::Process>],
    board_kernel: &'static kernel::Kernel,
    chip: &'static C,
    flash: &'static [u8],
    nv_flash: &'static F,
    fault_policy: &'static dyn ProcessFaultPolicy,
}

impl<
        F: 'static
            + hil::flash::Flash
            + hil::flash::HasClient<'static, NonvolatileToPages<'static, F>>, C: 'static + Chip,
    > ProcessLoaderComponent<F, C>
{
    pub fn new(
        processes: &'static mut [Option<&'static dyn process::Process>],
        board_kernel: &'static kernel::Kernel,
        chip: &'static C,
        flash: &'static [u8],
        nv_flash: &'static F,
        fault_policy: &'static dyn ProcessFaultPolicy,
    ) -> Self {
        Self {
            processes,
            board_kernel,
            chip,
            flash,
            nv_flash,
            fault_policy,
        }
    }
}

impl<
        F: 'static
            + hil::flash::Flash
            + hil::flash::HasClient<'static, NonvolatileToPages<'static, F>>, C: 'static + Chip,
    > Component for ProcessLoaderComponent<F, C>
{
    type StaticInput = (
        &'static mut MaybeUninit<<F as hil::flash::Flash>::Page>,
        &'static mut MaybeUninit<NonvolatileToPages<'static, F>>,
        &'static      mut MaybeUninit<DynamicProcessLoader<'static, C>>,
        &'static mut MaybeUninit<[u8; kernel::process_load_utilities::BUF_LEN]>,
    );
    type Output = &'static DynamicProcessLoader<'static, C>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {

        let buffer = static_buffer
            .3
            .write([0; kernel::process_load_utilities::BUF_LEN]);

        let flash_pagebuffer = static_buffer 
            .0
            .write(<F as hil::flash::Flash>::Page::default());

        let nv_to_page = static_buffer
            .1
            .write(NonvolatileToPages::new(self.nv_flash, flash_pagebuffer));
        hil::flash::HasClient::set_client(self.nv_flash, nv_to_page);

        let dynamic_process_loader = static_buffer.2.write(DynamicProcessLoader::new(
            self.processes,
            self.board_kernel,
            self.chip,
            self.flash,
            self.fault_policy,
            nv_to_page,
            buffer,
        ));
        hil::nonvolatile_storage::NonvolatileStorage::set_client(nv_to_page, dynamic_process_loader);
        dynamic_process_loader
    }
}
