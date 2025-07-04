// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2024.

//! Component for creating a sequential process loader.
//!
//! `ProcessLoaderSequentialComponent` uses the standard Tock assumptions about
//! where processes are stored in flash and what RAM is allocated for process
//! use.

use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::deferred_call::DeferredCallClient;
use kernel::hil::time::Counter;
use kernel::platform::chip::Chip;
use kernel::process::ProcessLoadingAsync;
use kernel::process::ProcessStandardDebug;

#[macro_export]
macro_rules! process_loader_sequential_component_static {
    ($C:ty, $D:ty, $NUMPROCS:expr, $T:ty $(,)?) => {{
        let loader = kernel::static_buf!(kernel::process::SequentialProcessLoaderMachine<
            $C, $D, $T
        >);
        let process_binary_array = kernel::static_buf!(
            [Option<kernel::process::ProcessBinary>; $NUMPROCS]
        );

       (loader, process_binary_array)
    };};
}

pub type ProcessLoaderSequentialComponentType<C, D, T> =
    kernel::process::SequentialProcessLoaderMachine<'static, C, D, T>;

pub struct ProcessLoaderSequentialComponent<
    C: Chip + 'static,
    D: ProcessStandardDebug + 'static,
    const NUM_PROCS: usize,
    T: Counter<'static> + 'static,
> {
    checker: &'static kernel::process::ProcessCheckerMachine,
    kernel: &'static kernel::Kernel,
    chip: &'static C,
    fault_policy: &'static dyn kernel::process::ProcessFaultPolicy,
    appid_policy: &'static dyn kernel::process_checker::AppIdPolicy,
    storage_policy: &'static dyn kernel::process::ProcessStandardStoragePermissionsPolicy<C, D>,
    app_flash: &'static [u8],
    app_memory: &'static mut [u8],
    timer: &'static T,
}

impl<C: Chip, D: ProcessStandardDebug, const NUM_PROCS: usize, T: Counter<'static> + 'static>
    ProcessLoaderSequentialComponent<C, D, NUM_PROCS, T>
{
    pub fn new(
        checker: &'static kernel::process::ProcessCheckerMachine,
        kernel: &'static kernel::Kernel,
        chip: &'static C,
        fault_policy: &'static dyn kernel::process::ProcessFaultPolicy,
        appid_policy: &'static dyn kernel::process_checker::AppIdPolicy,
        storage_policy: &'static dyn kernel::process::ProcessStandardStoragePermissionsPolicy<C, D>,
        app_flash: &'static [u8],
        app_memory: &'static mut [u8],
        timer: &'static T,
    ) -> Self {
        Self {
            checker,
            kernel,
            chip,
            fault_policy,
            appid_policy,
            storage_policy,
            app_flash,
            app_memory,
            timer,
        }
    }
}

impl<C: Chip, D: ProcessStandardDebug, const NUM_PROCS: usize, T: Counter<'static> + 'static>
    Component for ProcessLoaderSequentialComponent<C, D, NUM_PROCS, T>
{
    type StaticInput = (
        &'static mut MaybeUninit<kernel::process::SequentialProcessLoaderMachine<'static, C, D, T>>,
        &'static mut MaybeUninit<[Option<kernel::process::ProcessBinary>; NUM_PROCS]>,
    );

    type Output = &'static kernel::process::SequentialProcessLoaderMachine<'static, C, D, T>;

    fn finalize(self, s: Self::StaticInput) -> Self::Output {
        let proc_manage_cap =
            kernel::create_capability!(kernel::capabilities::ProcessManagementCapability);

        const ARRAY_REPEAT_VALUE: Option<kernel::process::ProcessBinary> = None;
        let process_binary_array = s.1.write([ARRAY_REPEAT_VALUE; NUM_PROCS]);

        let loader =
            s.0.write(kernel::process::SequentialProcessLoaderMachine::new(
                self.checker,
                process_binary_array,
                self.kernel,
                self.chip,
                self.app_flash,
                self.app_memory,
                self.fault_policy,
                self.storage_policy,
                self.appid_policy,
                &proc_manage_cap,
                self.timer,
            ));
        self.checker.set_client(loader);
        loader.register();
        loader.start();
        loader
    }
}
