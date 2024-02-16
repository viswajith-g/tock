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

use capsules_extra::app_loader::AppLoader;
use capsules_extra::nonvolatile_to_pages::NonvolatileToPages;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil;
use kernel::process_load_utilities;

// Setup static space for the objects.
#[macro_export]
macro_rules! app_loader_component_static {
    ($F:ty $(,)?) => {{
        let page = kernel::static_buf!(<$F as kernel::hil::flash::Flash>::Page);
        let ntp = kernel::static_buf!(
            capsules_extra::nonvolatile_to_pages::NonvolatileToPages<'static, $F>
        );
        let al = kernel::static_buf!(
            capsules_extra::app_loader::AppLoader<'static>
        );
        let buffer = kernel::static_buf!([u8; capsules_extra::app_loader::BUF_LEN]);

        (page, ntp, al, buffer)
    };};
}

pub struct AppLoaderComponent<
    F: 'static + hil::flash::Flash + hil::flash::HasClient<'static, NonvolatileToPages<'static, F>>,
> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    flash: &'static F,
    driver2: &'static dyn process_load_utilities::DynamicProcessLoading,
}

impl<
        F: 'static
            + hil::flash::Flash
            + hil::flash::HasClient<'static, NonvolatileToPages<'static, F>>,
    > AppLoaderComponent<F>
{
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        flash: &'static F,
        driver2: &'static dyn process_load_utilities::DynamicProcessLoading,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            flash,
            driver2,
        }
    }
}

impl<
        F: 'static
            + hil::flash::Flash
            + hil::flash::HasClient<'static, NonvolatileToPages<'static, F>>,
    > Component for AppLoaderComponent<F>
{
    type StaticInput = (
        &'static mut MaybeUninit<<F as hil::flash::Flash>::Page>,
        &'static mut MaybeUninit<NonvolatileToPages<'static, F>>,
        &'static mut MaybeUninit<AppLoader<'static>>,
        &'static mut MaybeUninit<[u8; capsules_extra::app_loader::BUF_LEN]>,
    );
    type Output = &'static AppLoader<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        let buffer = static_buffer
            .3
            .write([0; capsules_extra::app_loader::BUF_LEN]);

        let flash_pagebuffer = static_buffer
            .0
            .write(<F as hil::flash::Flash>::Page::default());

        let nv_to_page = static_buffer
            .1
            .write(NonvolatileToPages::new(self.flash, flash_pagebuffer));
        hil::flash::HasClient::set_client(self.flash, nv_to_page);

        let dynamic_app_loader = static_buffer.2.write(AppLoader::new(
            nv_to_page,
            self.driver2,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
            buffer,
        ));
        hil::nonvolatile_storage::NonvolatileStorage::set_client(nv_to_page, dynamic_app_loader);
        dynamic_app_loader
    }
}
