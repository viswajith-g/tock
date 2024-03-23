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
    () => {{
        let al = kernel::static_buf!(
            capsules_extra::app_loader::AppLoader<'static>
        );
        let buffer = kernel::static_buf!([u8; capsules_extra::app_loader::BUF_LEN]);

        (al, buffer)
    };};
}

pub struct AppLoaderComponent{
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    driver2: &'static dyn process_load_utilities::DynamicProcessLoading,
}

impl AppLoaderComponent
{
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        driver2: &'static dyn process_load_utilities::DynamicProcessLoading,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            driver2,
        }
    }
}

impl Component for AppLoaderComponent
{
    type StaticInput = (
        &'static mut MaybeUninit<AppLoader<'static>>,
        &'static mut MaybeUninit<[u8; capsules_extra::app_loader::BUF_LEN]>,
    );
    type Output = &'static AppLoader<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        let buffer = static_buffer
            .1
            .write([0; capsules_extra::app_loader::BUF_LEN]);

        let dynamic_app_loader = static_buffer.0.write(AppLoader::new(
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
            self.driver2,
            buffer,
        ));
        kernel::process_load_utilities::DynamicProcessLoading::set_client(self.driver2, dynamic_app_loader);
        dynamic_app_loader

    }
}
