// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! This provides kernel and userspace access to nonvolatile memory.
//!
//! This is an initial implementation that does not provide safety for
//! individual userland applications. Each application has full access to
//! the entire memory space that has been provided to userland. Future revisions
//! should update this to limit applications to only their allocated regions.
//!
//! However, the kernel accessible memory does not have to be the same range
//! as the userspace accessible address space. The kernel memory can overlap
//! if desired, or can be a completely separate range.
//!
//! Here is a diagram of the expected stack with this capsule:
//! Boxes are components and between the boxes are the traits that are the
//! interfaces between components. This capsule provides both a kernel and
//! userspace interface.
//!
//! ```text
//! +--------------------------------------------+     +--------------+
//! |                                            |     |              |
//! |                  kernel                    |     |  userspace   |
//! |                                            |     |              |
//! +--------------------------------------------+     +--------------+
//!  hil::nonvolatile_storage::NonvolatileStorage       kernel::Driver
//! +-----------------------------------------------------------------+
//! |                                                                 |
//! | capsules::nonvolatile_storage_driver::NonvolatileStorage (this) |
//! |                                                                 |
//! +-----------------------------------------------------------------+
//!            hil::nonvolatile_storage::NonvolatileStorage
//! +-----------------------------------------------------------------+
//! |                                                                 |
//! |               Physical nonvolatile storage driver               |
//! |                                                                 |
//! +-----------------------------------------------------------------+
//! ```
//!
//! Example instantiation:
//!
//! ```rust
//! # use kernel::static_init;
//!
//! let nonvolatile_storage = static_init!(
//!     capsules::nonvolatile_storage_driver::NonvolatileStorage<'static>,
//!     capsules::nonvolatile_storage_driver::NonvolatileStorage::new(
//!         fm25cl,                      // The underlying storage driver.
//!         board_kernel.create_grant(&grant_cap),     // Storage for app-specific state.
//!         3000,                        // The byte start address for the userspace
//!                                      // accessible memory region.
//!         2000,                        // The length of the userspace region.
//!         0,                           // The byte start address of the region
//!                                      // that is accessible by the kernel.
//!         3000,                        // The length of the kernel region.
//!         &mut capsules::nonvolatile_storage_driver::BUFFER));
//! hil::nonvolatile_storage::NonvolatileStorage::set_client(fm25cl, nonvolatile_storage);
//! ```

use core::cell::Cell;
use core::cmp;

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil;
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{ErrorCode, ProcessId};
// use kernel::platform::chip::Chip;
use kernel::process_load_utilities;
// use kernel::debug;

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

pub const BUF_LEN: usize = 512;             //4096 bytes to keep the nvmc page write function happy?

/// Variables that are stored in OTA_app grant region to support dynamic app load
// #[derive(Default)]
// struct ProcLoaderData {
//     //Index points the position where the entry point of a new app is written into PROCESS global array
//     index: usize,
//     // App size requested by ota app
//     appsize_requested_by_ota_app: usize,
//     // dynamic_flash_start_addr points the start address that a new app will be loaded
//     dynamic_flash_start_addr: usize,
//     // dynamic_unsued_sram_start_addr points the start address that a new app will use
//     dynamic_app_length: usize,
// }

#[derive(Clone, Copy, PartialEq)]
pub enum NonvolatileCommand {
    UserspaceRead,
    UserspaceWrite,
    // KernelRead,
    // KernelWrite,
}

#[derive(Clone, Copy)]
pub enum NonvolatileUser {
    App { processid: ProcessId },
    // Kernel,
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

// To set checks, etc.
#[derive(Copy, Clone, PartialEq)]
enum State {
    Idle,
    AppFlash,
    AppLoad,
}


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
    // What issued the currently executing call. This can be an app or the kernel.
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
        // new_app_start_addr: Cell<usize>,
        // new_app_length: Cell<usize>,
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
                    return Err(ErrorCode::INVAL);
                }
            }
            // NonvolatileCommand::KernelRead | NonvolatileCommand::KernelWrite => {
            //     // Because the kernel uses the NonvolatileStorage interface,
            //     // its calls are absolute addresses.
            //     if offset < self.kernel_start_address
            //         || offset >= self.kernel_start_address + self.kernel_length
            //         || length > self.kernel_length
            //         || offset + length > self.kernel_start_address + self.kernel_length
            //     {
            //         return Err(ErrorCode::INVAL);
            //     }
            // }
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
                             else{
                                // throws error otherwise about return type being ()
                                unimplemented!();
                             }
                            //else {
                            //     // Some app is using the storage, we must wait.
                            //     if app.pending_command {
                            //         // No more room in the queue, nowhere to store this
                            //         // request.
                            //         Err(ErrorCode::NOMEM)
                            //     } else {
                            //         // We can store this, so lets do it.
                            //         app.pending_command = true;
                            //         app.command = command;
                            //         app.offset = offset;
                            //         app.length = active_len;
                            //         Ok(())
                            //     }
                            // }
                        })
                        .unwrap_or_else(|err| Err(err.into()))
                })
            }
            // NonvolatileCommand::KernelRead | NonvolatileCommand::KernelWrite => {
            //     self.kernel_buffer
            //         .take()
            //         .map_or(Err(ErrorCode::NOMEM), |kernel_buffer| {
            //             let active_len = cmp::min(length, kernel_buffer.len());

            //             // Check if there is something going on.
            //             if self.current_user.is_none() {
            //                 // Nothing is using this, lets go!
            //                 self.current_user.set(NonvolatileUser::Kernel);

            //                 match command {
            //                     NonvolatileCommand::KernelRead => {
            //                         self.driver.read(kernel_buffer, offset, active_len)
            //                     }
            //                     NonvolatileCommand::KernelWrite => {
            //                         self.driver.write(kernel_buffer, offset, active_len)
            //                     }
            //                     _ => Err(ErrorCode::FAIL),
            //                 }
            //             } else {
            //                 if self.kernel_pending_command.get() {
            //                     Err(ErrorCode::NOMEM)
            //                 } else {
            //                     self.kernel_pending_command.set(true);
            //                     self.kernel_command.set(command);
            //                     self.kernel_readwrite_length.set(active_len);
            //                     self.kernel_readwrite_address.set(offset);
            //                     self.kernel_buffer.replace(kernel_buffer);
            //                     Ok(())
            //                 }
            //             }
            //         })
            // }
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
        let physical_address = self.new_app_start_addr.get();// offset + self.userspace_start_address;

        self.buffer
            .take()
            .map_or(Err(ErrorCode::RESERVE), |buffer| {
                // Check that the internal buffer and the buffer that was
                // allowed are long enough.
                let active_len = cmp::min(length, buffer.len());

                // self.current_app.set(Some(processid));
                match command {
                    NonvolatileCommand::UserspaceRead => {
                        self.driver1.read(buffer, physical_address, active_len)
                    }
                    NonvolatileCommand::UserspaceWrite => {
                        
                        self.driver1.write(buffer, physical_address, active_len)
                    }
                    _ => Err(ErrorCode::FAIL),
                }
            })
    }

    fn check_queue(&self) {
        // Check if there are any pending events.
        // if self.kernel_pending_command.get() {
        //     self.kernel_buffer.take().map(|kernel_buffer| {
        //         self.kernel_pending_command.set(false);
        //         self.current_user.set(NonvolatileUser::Kernel);

        //         match self.kernel_command.get() {
        //             NonvolatileCommand::KernelRead => self.driver1.read(
        //                 kernel_buffer,
        //                 self.kernel_readwrite_address.get(),
        //                 self.kernel_readwrite_length.get(),
        //             ),
        //             NonvolatileCommand::KernelWrite => self.driver1.write(
        //                 kernel_buffer,
        //                 self.kernel_readwrite_address.get(),
        //                 self.kernel_readwrite_length.get(),
        //             ),
        //             _ => Err(ErrorCode::FAIL),
        //         }
        //     });
        // } else {
            // If the kernel is not requesting anything, check all of the apps.
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
        // }
    }

    // fn check_offset_is_in_processes(
    //     &self,
    //     offset: usize,
    // ) -> Result<(), ErrorCode> {

    //     // debug!("offset: {}", offset);

    //     let mut index = 0;

    //     while index < self.supported_process_num
    //     {
    //         //We only refer to the two arrays
    //         let process_start_address =  self.process_region_start_address[index];
    //         let process_end_address = self.process_region_start_address[index] + self.process_region_size[index];
    //         // debug!("Process start address: {}, process end address: {}", process_start_address, process_end_address);

    //         let target = self.userspace_start_address + offset;
    //         // debug!("userspace address: {}", self.userspace_start_address);
    //         // debug!("target address: {}", target);

    //         if target >= process_start_address && target < process_end_address
    //         {
    //             return Err(ErrorCode::INVAL);
    //         }

    //         index += 1;

    //         // debug!("Index: {}", index);
    //     }

    //     return Ok(());
    // }
}

/// This is the callback client for the underlying physical storage driver.
impl hil::nonvolatile_storage::NonvolatileStorageClient for AppLoader<'_> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize) {
        // Switch on which user of this capsule generated this callback.
        self.current_user.take().map(|user| {
            match user {
                // NonvolatileUser::Kernel => {
                //     self.kernel_client.map(move |client| {
                //         client.read_done(buffer, length);
                //     });
                // }
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
                // NonvolatileUser::Kernel => {
                //     self.kernel_client.map(move |client| {
                //         client.write_done(buffer, length);
                //     });
                // }
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
    /// - `1`: Setup for loading app. 
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

            // 1 => {
            //     // How many bytes are accessible from userspace
            //     // TODO: Would break on 64-bit platforms
            //     CommandReturn::success_u32(self.userspace_length as u32)
            // }

            // 2 => {
            //     // Issue a read command
            //     let res = self.enqueue_command(
            //         NonvolatileCommand::UserspaceRead,
            //         arg1,
            //         arg2,
            //         Some(processid),
            //     );

            //     match res {
            //         Ok(()) => CommandReturn::success(),
            //         Err(e) => CommandReturn::failure(e),
            //     }
            // }

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

                // let offset_validity = self.check_offset_is_in_processes(arg1);
                // // debug!("offset: {}, length: {}, pid: {:?}", offset, length, processid);
                // // debug!("Offset validity: {:?}",offset_validity);
                // match offset_validity {
                //     Ok(()) => {
                //         let res =
                //             self.enqueue_command(
                //                 NonvolatileCommand::UserspaceWrite,
                //                 arg1,
                //                 arg2,
                //                 Some(processid),
                //             );
                //             // debug!("write command result: {:?}",res);

                //         match res {
                //             Ok(()) => CommandReturn::success(),
                //             Err(e) => CommandReturn::failure(e),
                //         }
                //     }
                //     Err(e) => CommandReturn::failure(e),
                // }
            //}

            3 => {
                // request kernel to load the new app
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


