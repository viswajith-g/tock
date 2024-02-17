// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! This capsule provides an interface between a dynamic loading userspace 
//! app and the kernel.
//!
//! This is an initial implementation that gets the app size from the 
//! userspace app and sets up the flash region in which the app will be
//! written. Then the app is actually written to flash. Finally, the
//! the userspace app sends a request for the app to be loaded.
//!
//!
//! Here is a diagram of the expected stack with this capsule:
//! Boxes are components and between the boxes are the traits that are the
//! interfaces between components. 
//!
//! ```text
//! +-----------------------------------------------------------------+
//! |                                                                 |
//! |                         userspace                               |
//! |                                                                 |
//! +-----------------------------------------------------------------+
//!                         kernel::Driver
//! +-----------------------------------------------------------------+
//! |                                                                 |
//! |               capsules::app_loader::AppLoader (this)            |
//! |                                                                 |
//! +-----------------------------------------------------------------+
//!            hil::nonvolatile_storage::NonvolatileStorage
//!        kernel::process_load_utilities::DynamicProcessLoading
//! +-----------------------------------------------------------------+
//! |                                                                 |
//! |               Kernel  | Physical Nonvolatile Storage            |
//! |                                                                 |
//! +-----------------------------------------------------------------+
//! ```
//!
//! Example instantiation:
//!
//! ```rust
//! # use kernel::static_init;
//!
//! let dynamic_app_loader = components::app_loader::AppLoaderComponent::new(
//!     board_kernel,
//!     capsules_extra::app_loader::DRIVER_NUM,
//!     &base_peripherals.nvmc,
//!     dynamic_process_loader,
//!     ).finalize(components::app_loader_component_static!(
//!                 nrf52840::nvmc::Nvmc));
//! ```

use core::cell::Cell;
use core::cmp;

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil;
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{ErrorCode, ProcessId};
use kernel::process_load_utilities;
use kernel::debug;

/// Syscall driver number.
use capsules_core::driver;
pub const DRIVER_NUM: usize = driver::NUM::AppLoader as usize;

/// IDs for subscribed upcalls.
mod upcall {
    /// Read done callback.
    pub const READ_DONE: usize = 0;
    /// Write done callback.
    pub const WRITE_DONE: usize = 1;
    /// Number of upcalls.
    pub const COUNT: u8 = 2;
}

/// Ids for read-only allow buffers
mod ro_allow {
    /// Setup a buffer to write bytes to the nonvolatile storage.
    pub const WRITE: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

/// Ids for read-write allow buffers
mod rw_allow {
    /// Setup a buffer to read from the nonvolatile storage into.
    pub const READ: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

pub const BUF_LEN: usize = 512;             

#[derive(Clone, Copy, PartialEq)]
pub enum NonvolatileCommand {
    UserspaceRead,
    UserspaceWrite,
}

#[derive(Clone, Copy)]
pub enum NonvolatileUser {
    App { processid: ProcessId },
}

pub struct App {
    pending_command: bool,
    command: NonvolatileCommand,
    offset: usize,
    length: usize,
}

impl Default for App {
    fn default() -> App {
        App {
            pending_command: false,
            command: NonvolatileCommand::UserspaceRead,
            offset: 0,
            length: 0,
        }
    }
}

// // To set checks, etc.
// #[derive(Copy, Clone, PartialEq)]
// enum State {
//     Idle,
//     AppFlash,
//     AppLoad,
// }



pub struct AppLoader<'a> {
    // The underlying physical storage device.
    driver1: &'a dyn hil::nonvolatile_storage::NonvolatileStorage<'a>, 
    driver2: &'a dyn process_load_utilities::DynamicProcessLoading,
    // Per-app state.
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >, 

    // Internal buffer for copying appslices into.
    buffer: TakeCell<'static, [u8]>,
    // What issued the currently executing call.
    current_user: OptionalCell<NonvolatileUser>,
    new_app_start_addr: Cell<usize>,
    new_app_length: Cell<usize>,
}

impl<'a> AppLoader<'a> {
    pub fn new(
        driver1: &'a dyn hil::nonvolatile_storage::NonvolatileStorage<'a>, 
        driver2: &'a dyn process_load_utilities::DynamicProcessLoading, 
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        buffer: &'static mut [u8],
    ) -> AppLoader<'a> {
        AppLoader {
            driver1: driver1,
            driver2: driver2,
            apps: grant,
            buffer: TakeCell::new(buffer),
            current_user: OptionalCell::empty(),
            new_app_start_addr: Cell::new(0),
            new_app_length: Cell::new(0),
        }
    }

    // Check so see if we are doing something. If not, go ahead and do this
    // command. If so, this is queued and will be run when the pending
    // command completes.
    fn enqueue_command(
        &self,
        command: NonvolatileCommand,
        offset: usize,
        length: usize,
        processid: Option<ProcessId>,
    ) -> Result<(), ErrorCode> {
        // Do bounds check.
        match command {
            NonvolatileCommand::UserspaceRead | NonvolatileCommand::UserspaceWrite => {
                // Userspace sees memory that starts at address 0 even if it
                // is offset in the physical memory.
                if offset >= self.new_app_start_addr.get()
                    || length > self.new_app_length.get()
                    || offset + length > self.new_app_length.get()
                {
                    debug!("Invalid bounds!\n");
                    return Err(ErrorCode::INVAL);
                }
                debug!("offset: {}\n length: {}\n", offset, length);
            }
        }

        // Do very different actions if this is a call from userspace
        // or from the kernel.
        match command {
            NonvolatileCommand::UserspaceRead | NonvolatileCommand::UserspaceWrite => {
                processid.map_or(Err(ErrorCode::FAIL), |processid| {
                    self.apps
                        .enter(processid, |app, kernel_data| {
                            // Get the length of the correct allowed buffer.
                            let allow_buf_len = match command {
                                NonvolatileCommand::UserspaceRead => kernel_data
                                    .get_readwrite_processbuffer(rw_allow::READ)
                                    .map_or(0, |read| read.len()),
                                NonvolatileCommand::UserspaceWrite => kernel_data
                                    .get_readonly_processbuffer(ro_allow::WRITE)
                                    .map_or(0, |read| read.len()),
                                _ => 0,
                            };

                            // Check that it exists.
                            if allow_buf_len == 0 || self.buffer.is_none() {
                                return Err(ErrorCode::RESERVE);
                            }

                            // Shorten the length if the application gave us nowhere to
                            // put it.
                            let active_len = cmp::min(length, allow_buf_len);

                            // First need to determine if we can execute this or must
                            // queue it.
                            if self.current_user.is_none() {
                                // No app is currently using the underlying storage.
                                // Mark this app as active, and then execute the command.
                                self.current_user.set(NonvolatileUser::App {
                                    processid: processid,
                                });

                                // Need to copy bytes if this is a write!
                                if command == NonvolatileCommand::UserspaceWrite {
                                    debug!("userspace_write command matched");
                                    let _ = kernel_data
                                        .get_readonly_processbuffer(ro_allow::WRITE)
                                        .and_then(|write| {
                                            write.enter(|app_buffer| {
                                                self.buffer.map(|kernel_buffer| {
                                                    // Check that the internal buffer and the buffer that was
                                                    // allowed are long enough.

                                                    // also check for tbf header validity (TODO)
                                                    let write_len =
                                                        cmp::min(active_len, kernel_buffer.len());

                                                    debug!("write len: {}", write_len);

                                                    let d = &app_buffer[0..write_len];
                                                    for (i, c) in kernel_buffer[0..write_len]
                                                        .iter_mut()
                                                        .enumerate()
                                                    {
                                                        *c = d[i].get();
                                                    }
                                                });
                                            })
                                        });
                                }

                                self.userspace_call_driver(command, offset, active_len)
                             } 
                            else {  
                                // Some app is using the storage, we must wait.
                                if app.pending_command {
                                    // No more room in the queue, nowhere to store this
                                    // request.
                                    Err(ErrorCode::NOMEM)
                                } else {
                                    // We can store this, so lets do it.
                                    app.pending_command = true;
                                    app.command = command;
                                    app.offset = offset;
                                    app.length = active_len;
                                    Ok(())
                                }
                            }
                        })
                        .unwrap_or_else(|err| Err(err.into()))
                })
            }
        }
    }

    fn userspace_call_driver(
        &self,
        command: NonvolatileCommand,
        offset: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {
        // Calculate where we want to actually read from in the physical
        // storage.
        let physical_address = offset + self.new_app_start_addr.get();// offset + self.userspace_start_address;

        debug!("physical address for write: {}\n", physical_address);

        self.buffer
            .take()
            .map_or(Err(ErrorCode::RESERVE), |buffer| {
                // Check that the internal buffer and the buffer that was
                // allowed are long enough.
                let active_len = cmp::min(length, buffer.len());
                debug!("active length: {}\n", active_len);

                // self.current_app.set(Some(processid));
                match command {
                    NonvolatileCommand::UserspaceRead => {
                        self.driver1.read(buffer, physical_address, active_len)
                    }
                    NonvolatileCommand::UserspaceWrite => {
                        debug!("writing to flash\n");
                        self.driver1.write(buffer, physical_address, active_len)
                    }
                    _ => Err(ErrorCode::FAIL),
                }
            })
    }

    fn check_queue(&self) {
        // Check all of the apps.
            for cntr in self.apps.iter() {
                let processid = cntr.processid();
                let started_command = cntr.enter(|app, _| {
                    if app.pending_command {
                        app.pending_command = false;
                        self.current_user.set(NonvolatileUser::App {
                            processid: processid,
                        });
                        if let Ok(()) =
                            self.userspace_call_driver(app.command, app.offset, app.length)
                        {
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });
                if started_command {
                    break;
                }
            }
    }
}

/// This is the callback client for the underlying physical storage driver.
impl hil::nonvolatile_storage::NonvolatileStorageClient for AppLoader<'_> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize) {
        // Switch on which user of this capsule generated this callback.
        self.current_user.take().map(|user| {
            match user {
                NonvolatileUser::App { processid } => {
                    let _ = self.apps.enter(processid, move |_, kernel_data| {
                        // Need to copy in the contents of the buffer
                        let _ = kernel_data
                            .get_readwrite_processbuffer(rw_allow::READ)
                            .and_then(|read| {
                                read.mut_enter(|app_buffer| {
                                    let read_len = cmp::min(app_buffer.len(), length);

                                    let d = &app_buffer[0..read_len];
                                    for (i, c) in buffer[0..read_len].iter().enumerate() {
                                        d[i].set(*c);
                                    }
                                })
                            });

                        // Replace the buffer we used to do this read.
                        self.buffer.replace(buffer);

                        // And then signal the app.
                        kernel_data
                            .schedule_upcall(upcall::READ_DONE, (length, 0, 0))
                            .ok();
                    });
                }   
            }
        });

        self.check_queue();
    }

    fn write_done(&self, buffer: &'static mut [u8], length: usize) {
        // Switch on which user of this capsule generated this callback.
        self.current_user.take().map(|user| {
            match user {
                NonvolatileUser::App { processid } => {
                    let _ = self.apps.enter(processid, move |_app, kernel_data| {
                        // Replace the buffer we used to do this write.
                        self.buffer.replace(buffer);

                        // And then signal the app.
                        kernel_data
                            .schedule_upcall(upcall::WRITE_DONE, (length, 0, 0))
                            .ok();
                    });
                }
            }
        });

        self.check_queue();
    }
}

/// Provide an interface for userland.
impl SyscallDriver for AppLoader<'_> {
    /// Command interface.
    ///
    /// Commands are selected by the lowest 8 bits of the first argument.
    ///
    /// ### `command_num`
    ///
    /// - `0`: Return Ok(()) if this driver is included on the platform.
    /// - `1`: Request kernel to setup for loading app. 
    /// - `2`: Start a write to the nonvolatile_storage.
    /// - `3`: Request kernel to load app.

    fn command(
        &self,
        command_num: usize,
        arg1: usize,
        arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num {
            0 => CommandReturn::success(),

            1 => {
                //setup phase
                let res = self.driver2.setup(arg1);     // pass the size of the app to the setup function
                match res {
                    Ok((start_addr, app_len)) => {
                        self.new_app_start_addr.set(start_addr); 
                        self.new_app_length.set(app_len);
                        debug!("Start Address: {}\n
                                App Length: {}\n", start_addr, app_len);
                        CommandReturn::success()
                    },
                    
                    Err(e) => CommandReturn::failure(e),
                }
            }

            2 => {
                // Issue a write command
                    let res = self.enqueue_command(
                        NonvolatileCommand::UserspaceWrite,
                        arg1,
                        arg2,
                        Some(processid),
                    );

                    match res {
                        Ok(()) => CommandReturn::success(),
                        Err(e) => CommandReturn::failure(e),
                    }
                }

            3 => {
                // Request kernel to load the new app
                let res = self.driver2.load();
                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}


