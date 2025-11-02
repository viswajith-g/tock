// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Helper functions and machines for loading process binaries into in-memory
//! Tock processes.
//!
//! Process loaders are responsible for parsing the binary formats of Tock
//! processes, checking whether they are allowed to be loaded, and if so
//! initializing a process structure to run it.
//!
//! This module provides multiple process loader options depending on which
//! features a particular board requires.

use core::cell::Cell;
use core::fmt;

use crate::capabilities::ProcessManagementCapability;
use crate::config;
use crate::debug;
use crate::deferred_call::{DeferredCall, DeferredCallClient};
use crate::kernel::Kernel;
use crate::platform::chip::Chip;
use crate::process::{Process, ShortId};
use crate::process_binary::{ProcessBinary, ProcessBinaryError};
use crate::process_checker::AcceptedCredential;
use crate::process_checker::{AppIdPolicy, ProcessCheckError, ProcessCheckerMachine};
use crate::process_policies::ProcessFaultPolicy;
use crate::process_policies::ProcessStandardStoragePermissionsPolicy;
use crate::process_standard::ProcessStandard;
use crate::process_standard::{ProcessStandardDebug, ProcessStandardDebugFull};
use crate::utilities::cells::{MapCell, OptionalCell};

/// Errors that can occur when trying to load and create processes.
pub enum ProcessLoadError {
    /// Not enough memory to meet the amount requested by a process. Modify the
    /// process to request less memory, flash fewer processes, or increase the
    /// size of the region your board reserves for process memory.
    NotEnoughMemory,

    /// A process was loaded with a length in flash that the MPU does not
    /// support. The fix is probably to correct the process size, but this could
    /// also be caused by a bad MPU implementation.
    MpuInvalidFlashLength,

    /// The MPU configuration failed for some other, unspecified reason. This
    /// could be of an internal resource exhaustion, or a mismatch between the
    /// (current) MPU constraints and process requirements.
    MpuConfigurationError,

    /// A process specified a fixed memory address that it needs its memory
    /// range to start at, and the kernel did not or could not give the process
    /// a memory region starting at that address.
    MemoryAddressMismatch {
        actual_address: u32,
        expected_address: u32,
    },

    /// There is nowhere in the `PROCESSES` array to store this process.
    NoProcessSlot,

    /// Process loading failed because parsing the binary failed.
    BinaryError(ProcessBinaryError),

    /// Process loading failed because checking the process failed.
    CheckError(ProcessCheckError),

    /// Process loading error due (likely) to a bug in the kernel. If you get
    /// this error please open a bug report.
    InternalError,
}

impl fmt::Debug for ProcessLoadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcessLoadError::NotEnoughMemory => {
                write!(f, "Not able to provide RAM requested by app")
            }

            ProcessLoadError::MpuInvalidFlashLength => {
                write!(f, "App flash length not supported by MPU")
            }

            ProcessLoadError::MpuConfigurationError => {
                write!(f, "Configuring the MPU failed")
            }

            ProcessLoadError::MemoryAddressMismatch {
                actual_address,
                expected_address,
            } => write!(
                f,
                "App memory does not match requested address Actual:{:#x}, Expected:{:#x}",
                actual_address, expected_address
            ),

            ProcessLoadError::NoProcessSlot => {
                write!(f, "Nowhere to store the loaded process")
            }

            ProcessLoadError::BinaryError(binary_error) => {
                writeln!(f, "Error parsing process binary")?;
                write!(f, "{:?}", binary_error)
            }

            ProcessLoadError::CheckError(check_error) => {
                writeln!(f, "Error checking process")?;
                write!(f, "{:?}", check_error)
            }

            ProcessLoadError::InternalError => write!(f, "Error in kernel. Likely a bug."),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// SYNCHRONOUS PROCESS LOADING
////////////////////////////////////////////////////////////////////////////////

/// Load processes into runnable process structures.
///
/// Load processes (stored as TBF objects in flash) into runnable process
/// structures stored in the `procs` array and mark all successfully loaded
/// processes as runnable. This method does not check the cryptographic
/// credentials of TBF objects. Platforms for which code size is tight and do
/// not need to check TBF credentials can call this method because it results in
/// a smaller kernel, as it does not invoke the credential checking state
/// machine.
///
/// This function is made `pub` so that board files can use it, but loading
/// processes from slices of flash an memory is fundamentally unsafe. Therefore,
/// we require the `ProcessManagementCapability` to call this function.
// Mark inline always to reduce code size. Since this is only called in one
// place (a board's main.rs), by inlining the load_*processes() functions, the
// compiler can elide many checks which reduces code size appreciably. Note,
// however, these functions require a rather large stack frame, which may be an
// issue for boards small kernel stacks.
#[inline(always)]
pub fn load_processes<C: Chip>(
    kernel: &'static Kernel,
    chip: &'static C,
    app_flash: &'static [u8],
    app_memory: &'static mut [u8],
    fault_policy: &'static dyn ProcessFaultPolicy,
    _capability_management: &dyn ProcessManagementCapability,
) -> Result<(), ProcessLoadError> {
    load_processes_from_flash::<C, ProcessStandardDebugFull>(
        kernel,
        chip,
        app_flash,
        app_memory,
        fault_policy,
    )?;

    if config::CONFIG.debug_process_credentials {
        debug!("Checking: no checking, load and run all processes");
        for proc in kernel.get_process_iter() {
            debug!("Running {}", proc.get_process_name());
        }
    }
    Ok(())
}

/// Helper function to load processes from flash into an array of active
/// processes. This is the default template for loading processes, but a board
/// is able to create its own `load_processes()` function and use that instead.
///
/// Processes are found in flash starting from the given address and iterating
/// through Tock Binary Format (TBF) headers. Processes are given memory out of
/// the `app_memory` buffer until either the memory is exhausted or the
/// allocated number of processes are created. This buffer is a non-static slice,
/// ensuring that this code cannot hold onto the slice past the end of this function
/// (instead, processes store a pointer and length), which necessary for later
/// creation of `ProcessBuffer`s in this memory region to be sound.
/// A reference to each process is stored in the provided `procs` array.
/// How process faults are handled by the
/// kernel must be provided and is assigned to every created process.
///
/// Returns `Ok(())` if process discovery went as expected. Returns a
/// `ProcessLoadError` if something goes wrong during TBF parsing or process
/// creation.
#[inline(always)]
fn load_processes_from_flash<C: Chip, D: ProcessStandardDebug + 'static>(
    kernel: &'static Kernel,
    chip: &'static C,
    app_flash: &'static [u8],
    app_memory: &'static mut [u8],
    fault_policy: &'static dyn ProcessFaultPolicy,
) -> Result<(), ProcessLoadError> {
    if config::CONFIG.debug_load_processes {
        debug!(
            "Loading processes from flash={:#010X}-{:#010X} into sram={:#010X}-{:#010X}",
            app_flash.as_ptr() as usize,
            app_flash.as_ptr() as usize + app_flash.len() - 1,
            app_memory.as_ptr() as usize,
            app_memory.as_ptr() as usize + app_memory.len() - 1
        );
    }

    let mut remaining_flash = app_flash;
    let mut remaining_memory = app_memory;

    loop {
        match kernel.next_available_process_slot() {
            Ok((index, slot)) => {
                let load_binary_result = discover_process_binary(remaining_flash);

                match load_binary_result {
                    Ok((new_flash, process_binary)) => {
                        remaining_flash = new_flash;

                        let load_result = load_process::<C, D>(
                            kernel,
                            chip,
                            process_binary,
                            remaining_memory,
                            ShortId::LocallyUnique,
                            index,
                            fault_policy,
                            &(),
                        );
                        match load_result {
                            Ok((new_mem, proc)) => {
                                remaining_memory = new_mem;
                                match proc {
                                    Some(p) => {
                                        if config::CONFIG.debug_load_processes {
                                            debug!("Loaded process {}", p.get_process_name())
                                        }
                                        slot.set(p);
                                    }
                                    None => {
                                        if config::CONFIG.debug_load_processes {
                                            debug!("No process loaded.");
                                        }
                                    }
                                }
                            }
                            Err((new_mem, err)) => {
                                remaining_memory = new_mem;
                                if config::CONFIG.debug_load_processes {
                                    debug!("Processes load error: {:?}.", err);
                                }
                            }
                        }
                    }
                    Err((new_flash, err)) => {
                        remaining_flash = new_flash;
                        match err {
                            ProcessBinaryError::NotEnoughFlash
                            | ProcessBinaryError::TbfHeaderNotFound => {
                                if config::CONFIG.debug_load_processes {
                                    debug!("No more processes to load: {:?}.", err);
                                }
                                // No more processes to load.
                                break;
                            }

                            ProcessBinaryError::TbfHeaderParseFailure(_)
                            | ProcessBinaryError::IncompatibleKernelVersion { .. }
                            | ProcessBinaryError::IncorrectFlashAddress { .. }
                            | ProcessBinaryError::NotEnabledProcess
                            | ProcessBinaryError::Padding => {
                                if config::CONFIG.debug_load_processes {
                                    debug!("Unable to use process binary: {:?}.", err);
                                }

                                // Skip this binary and move to the next one.
                                continue;
                            }
                        }
                    }
                }
            }
            Err(()) => {
                // No slot available.
                if config::CONFIG.debug_load_processes {
                    debug!("No more process slots to load processes into.");
                }
                break;
            }
        }
    }
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

/// Find a process binary stored at the beginning of `flash` and create a
/// `ProcessBinary` object if the process is viable to run on this kernel.
fn discover_process_binary(
    flash: &'static [u8],
) -> Result<(&'static [u8], ProcessBinary), (&'static [u8], ProcessBinaryError)> {
    if config::CONFIG.debug_load_processes {
        debug!(
            "Looking for process binary in flash={:#010X}-{:#010X}",
            flash.as_ptr() as usize,
            flash.as_ptr() as usize + flash.len() - 1
        );
    }

    // If this fails, not enough remaining flash to check for an app.
    let test_header_slice = flash
        .get(0..8)
        .ok_or((flash, ProcessBinaryError::NotEnoughFlash))?;

    // Pass the first eight bytes to tbfheader to parse out the length of
    // the tbf header and app. We then use those values to see if we have
    // enough flash remaining to parse the remainder of the header.
    //
    // Start by converting [u8] to [u8; 8].
    let header = test_header_slice
        .try_into()
        .or(Err((flash, ProcessBinaryError::NotEnoughFlash)))?;

    let (version, header_length, app_length) =
        match tock_tbf::parse::parse_tbf_header_lengths(header) {
            Ok((v, hl, el)) => (v, hl, el),
            Err(tock_tbf::types::InitialTbfParseError::InvalidHeader(app_length)) => {
                // If we could not parse the header, then we want to skip over
                // this app and look for the next one.
                (0, 0, app_length)
            }
            Err(tock_tbf::types::InitialTbfParseError::UnableToParse) => {
                // Since Tock apps use a linked list, it is very possible the
                // header we started to parse is intentionally invalid to signal
                // the end of apps. This is ok and just means we have finished
                // loading apps.
                return Err((flash, ProcessBinaryError::TbfHeaderNotFound));
            }
        };

    // Now we can get a slice which only encompasses the length of flash
    // described by this tbf header.  We will either parse this as an actual
    // app, or skip over this region.
    let app_flash = flash
        .get(0..app_length as usize)
        .ok_or((flash, ProcessBinaryError::NotEnoughFlash))?;

    // Advance the flash slice for process discovery beyond this last entry.
    // This will be the start of where we look for a new process since Tock
    // processes are allocated back-to-back in flash.
    let remaining_flash = flash
        .get(app_flash.len()..)
        .ok_or((flash, ProcessBinaryError::NotEnoughFlash))?;

    let pb = ProcessBinary::create(app_flash, header_length as usize, version, true)
        .map_err(|e| (remaining_flash, e))?;

    Ok((remaining_flash, pb))
}

/// Load a process stored as a TBF process binary with `app_memory` as the RAM
/// pool that its RAM should be allocated from. Returns `Ok` if the process
/// object was created, `Err` with a relevant error if the process object could
/// not be created.
fn load_process<C: Chip, D: ProcessStandardDebug>(
    kernel: &'static Kernel,
    chip: &'static C,
    process_binary: ProcessBinary,
    app_memory: &'static mut [u8],
    app_id: ShortId,
    index: usize,
    fault_policy: &'static dyn ProcessFaultPolicy,
    storage_policy: &'static dyn ProcessStandardStoragePermissionsPolicy<C, D>,
) -> Result<(&'static mut [u8], Option<&'static dyn Process>), (&'static mut [u8], ProcessLoadError)>
{
    if config::CONFIG.debug_load_processes {
        debug!(
            "Loading: process flash={:#010X}-{:#010X} ram={:#010X}-{:#010X}",
            process_binary.flash.as_ptr() as usize,
            process_binary.flash.as_ptr() as usize + process_binary.flash.len() - 1,
            app_memory.as_ptr() as usize,
            app_memory.as_ptr() as usize + app_memory.len() - 1
        );
    }

    // Need to reassign remaining_memory in every iteration so the compiler
    // knows it will not be re-borrowed.
    // If we found an actual app header, try to create a `Process`
    // object. We also need to shrink the amount of remaining memory
    // based on whatever is assigned to the new process if one is
    // created.

    // Try to create a process object from that app slice. If we don't
    // get a process and we didn't get a loading error (aka we got to
    // this point), then the app is a disabled process or just padding.
    let (process_option, unused_memory) = unsafe {
        ProcessStandard::<C, D>::create(
            kernel,
            chip,
            process_binary,
            app_memory,
            fault_policy,
            storage_policy,
            app_id,
            index,
        )
        .map_err(|(e, memory)| (memory, e))?
    };

    process_option.map(|process| {
        if config::CONFIG.debug_load_processes {
            debug!(
                "Loading: {} [{}] flash={:#010X}-{:#010X} ram={:#010X}-{:#010X}",
                process.get_process_name(),
                index,
                process.get_addresses().flash_start,
                process.get_addresses().flash_end,
                process.get_addresses().sram_start,
                process.get_addresses().sram_end - 1,
            );
        }
    });

    Ok((unused_memory, process_option))
}

////////////////////////////////////////////////////////////////////////////////
// ASYNCHRONOUS PROCESS LOADING
////////////////////////////////////////////////////////////////////////////////

/// Client for asynchronous process loading.
///
/// This supports a client that is notified after trying to load each process in
/// flash. Also there is a callback for after all processes have been
/// discovered.
pub trait ProcessLoadingAsyncClient {
    /// A process was successfully found in flash, checked, and loaded into a
    /// `ProcessStandard` object.
    fn process_loaded(&self, result: Result<(), ProcessLoadError>);

    /// There are no more processes in flash to be loaded.
    fn process_loading_finished(&self);
}

/// Asynchronous process loading.
///
/// Machines which implement this trait perform asynchronous process loading and
/// signal completion through `ProcessLoadingAsyncClient`.
///
/// Various process loaders may exist. This includes a loader from a MCU's
/// integrated flash, or a loader from an external flash chip.
pub trait ProcessLoadingAsync<'a> {
    /// Set the client to receive callbacks about process loading and when
    /// process loading has finished.
    fn set_client(&self, client: &'a dyn ProcessLoadingAsyncClient);

    /// Set the credential checking policy for the loader.
    fn set_policy(&self, policy: &'a dyn AppIdPolicy);

    /// Start the process loading operation.
    fn start(&self);
}

/// Operating mode of the loader.
#[derive(Clone, Copy, Debug)]
enum SequentialProcessLoaderMachineState {
    /// Phase of discovering `ProcessBinary` objects in flash.
    DiscoverProcessBinaries,
    /// Phase of loading `ProcessBinary`s into `Process`es.
    LoadProcesses,
}

/// Operating mode of the sequential process loader.
///
/// The loader supports loading processes from flash at boot, and loading processes
/// that were written to flash dynamically at runtime. Most of the internal logic is the
/// same (and therefore reused), but we need to track which mode of operation the
/// loader is in.
#[derive(Clone, Copy)]
enum SequentialProcessLoaderMachineRunMode {
    /// The loader was called by a board's main function at boot.
    BootMode,
    /// The loader was called by a dynamic process loader at runtime.
    RuntimeMode,
}

/// Enum to hold the padding requirements for a new application.
#[derive(Clone, Copy, PartialEq, Default)]
pub enum PaddingRequirement {
    #[default]
    None,
    PrePad,
    PostPad,
    PreAndPostPad,
}

////////////////////////////////////////////////////////////////////////////////
// BINARY DISCOVERY TABLE (BDT) READING
////////////////////////////////////////////////////////////////////////////////

// BDT constants (must match bootloader)
const BDT_ADDR: usize = 0x8000;
const BDT_MAGIC: [u8; 4] = *b"BDTS";
const MAX_KERNEL_ENTRIES: usize = 120;

const BINARY_TYPE_KERNEL: u8 = 0x01;

/// Binary entry from BDT
#[derive(Copy, Clone, Debug)]
struct BinaryEntry {
    start_address: u32,
    size: u32,
    version: [u8; 3],
    binary_type: u8,
    reserved: [u8; 4],
}

impl BinaryEntry {
    fn is_valid(&self) -> bool {
        self.start_address >= 0x9000
            && self.size > 0
            && self.start_address < 0x100000
            && self.size < 0x100000
    }
}

/// BDT Header
#[derive(Copy, Clone)]
struct BdtHeader {
    magic: [u8; 4],
    kernel_count: u16,
    app_count: u16,
    reserved: [u8; 8],
}

/// Read BDT from flash
fn read_bdt() -> Option<(BdtHeader, [BinaryEntry; MAX_KERNEL_ENTRIES])> {
    let bdt_ptr = BDT_ADDR as *const u8;
    
    // Read header (16 bytes)
    let header = unsafe {
        BdtHeader {
            magic: [
                bdt_ptr.read_volatile(),
                bdt_ptr.add(1).read_volatile(),
                bdt_ptr.add(2).read_volatile(),
                bdt_ptr.add(3).read_volatile(),
            ],
            kernel_count: u16::from_le_bytes([
                bdt_ptr.add(4).read_volatile(),
                bdt_ptr.add(5).read_volatile(),
            ]),
            app_count: u16::from_le_bytes([
                bdt_ptr.add(6).read_volatile(),
                bdt_ptr.add(7).read_volatile(),
            ]),
            reserved: [0; 8], // Skip reserved bytes
        }
    };
    
    // Check magic
    if header.magic != BDT_MAGIC {
        return None;
    }
    
    // Read kernel entries (start at offset 16)
    let mut kernel_entries = [BinaryEntry {
        start_address: 0,
        size: 0,
        version: [0; 3],
        binary_type: 0,
        reserved: [0; 4],
    }; MAX_KERNEL_ENTRIES];
    
    let entries_start = unsafe { bdt_ptr.add(16) };
    for i in 0..kernel_entries.len() {
        let entry_ptr = unsafe { entries_start.add(i * 16) };
        kernel_entries[i] = unsafe {
            BinaryEntry {
                start_address: u32::from_le_bytes([
                    entry_ptr.read_volatile(),
                    entry_ptr.add(1).read_volatile(),
                    entry_ptr.add(2).read_volatile(),
                    entry_ptr.add(3).read_volatile(),
                ]),
                size: u32::from_le_bytes([
                    entry_ptr.add(4).read_volatile(),
                    entry_ptr.add(5).read_volatile(),
                    entry_ptr.add(6).read_volatile(),
                    entry_ptr.add(7).read_volatile(),
                ]),
                version: [
                    entry_ptr.add(8).read_volatile(),
                    entry_ptr.add(9).read_volatile(),
                    entry_ptr.add(10).read_volatile(),
                ],
                binary_type: entry_ptr.add(11).read_volatile(),
                reserved: [0; 4],
            }
        };
    }
    
    Some((header, kernel_entries))
}

/// Flash exclusion region
#[derive(Copy, Clone, Debug)]
struct ExclusionRegion {
    start: usize,
    end: usize,
}

////////////////////////////////////////////////////////////////////////////////
// SEQUENTIAL PROCESS LOADING MACHINE
////////////////////////////////////////////////////////////////////////////////

/// A machine for loading processes stored sequentially in a region of flash.
///
/// Load processes (stored as TBF objects in flash) into runnable process
/// structures stored in the `procs` array. This machine scans the footers in
/// the TBF for cryptographic credentials for binary integrity, passing them to
/// the checker to decide whether the process has sufficient credentials to run.
pub struct SequentialProcessLoaderMachine<'a, C: Chip + 'static, D: ProcessStandardDebug + 'static>
{
    /// Client to notify as processes are loaded and process loading finishes after boot.
    boot_client: OptionalCell<&'a dyn ProcessLoadingAsyncClient>,
    /// Client to notify as processes are loaded and process loading finishes during runtime.
    runtime_client: OptionalCell<&'a dyn ProcessLoadingAsyncClient>,
    /// Machine to use to check process credentials.
    checker: &'static ProcessCheckerMachine,
    /// Array to store `ProcessBinary`s after checking credentials.
    proc_binaries: MapCell<&'static mut [Option<ProcessBinary>]>,
    /// Total available flash for process binaries on this board.
    flash_bank: Cell<&'static [u8]>,
    /// Flash memory region to load processes from.
    flash: Cell<&'static [u8]>,
    /// Memory available to assign to applications.
    app_memory: Cell<&'static mut [u8]>,
    /// Mechanism for generating async callbacks.
    deferred_call: DeferredCall,
    /// Reference to the kernel object for creating Processes.
    kernel: &'static Kernel,
    /// Reference to the Chip object for creating Processes.
    chip: &'static C,
    /// The policy to use when determining ShortIds and process uniqueness.
    policy: OptionalCell<&'a dyn AppIdPolicy>,
    /// The fault policy to assign to each created Process.
    fault_policy: &'static dyn ProcessFaultPolicy,
    /// The storage permissions policy to assign to each created Process.
    storage_policy: &'static dyn ProcessStandardStoragePermissionsPolicy<C, D>,
    /// Current mode of the loading machine.
    state: OptionalCell<SequentialProcessLoaderMachineState>,
    /// Current operating mode of the loading machine.
    run_mode: OptionalCell<SequentialProcessLoaderMachineRunMode>,
}

impl<'a, C: Chip, D: ProcessStandardDebug> SequentialProcessLoaderMachine<'a, C, D> {
    /// This function is made `pub` so that board files can use it, but loading
    /// processes from slices of flash an memory is fundamentally unsafe.
    /// Therefore, we require the `ProcessManagementCapability` to call this
    /// function.
    pub fn new(
        checker: &'static ProcessCheckerMachine,
        proc_binaries: &'static mut [Option<ProcessBinary>],
        kernel: &'static Kernel,
        chip: &'static C,
        flash: &'static [u8],
        app_memory: &'static mut [u8],
        fault_policy: &'static dyn ProcessFaultPolicy,
        storage_policy: &'static dyn ProcessStandardStoragePermissionsPolicy<C, D>,
        policy: &'static dyn AppIdPolicy,
        _capability_management: &dyn ProcessManagementCapability,
    ) -> Self {
        Self {
            deferred_call: DeferredCall::new(),
            checker,
            boot_client: OptionalCell::empty(),
            runtime_client: OptionalCell::empty(),
            run_mode: OptionalCell::empty(),
            proc_binaries: MapCell::new(proc_binaries),
            kernel,
            chip,
            flash_bank: Cell::new(flash),
            flash: Cell::new(flash),
            app_memory: Cell::new(app_memory),
            policy: OptionalCell::new(policy),
            fault_policy,
            storage_policy,
            state: OptionalCell::empty(),
        }
    }

    /// Set the runtime client to receive callbacks about process loading and when
    /// process loading has finished.
    pub fn set_runtime_client(&self, client: &'a dyn ProcessLoadingAsyncClient) {
        self.runtime_client.set(client);
    }

    /// Find the current active client based on the operation mode.
    fn get_current_client(&self) -> Option<&dyn ProcessLoadingAsyncClient> {
        match self.run_mode.get()? {
            SequentialProcessLoaderMachineRunMode::BootMode => self.boot_client.get(),
            SequentialProcessLoaderMachineRunMode::RuntimeMode => self.runtime_client.get(),
        }
    }

    /// Find a slot in the `PROCESS_BINARIES` array to store this process.
    fn find_open_process_binary_slot(&self) -> Option<usize> {
        self.proc_binaries.map_or(None, |proc_bins| {
            for (i, p) in proc_bins.iter().enumerate() {
                if p.is_none() {
                    return Some(i);
                }
            }
            None
        })
    }

    /// Helper function to find the next potential aligned address for the
    /// new app with size `app_length` assuming Cortex-M alignment rules.
    fn find_next_cortex_m_aligned_address(&self, address: usize, app_length: usize) -> usize {
        let remaining = address % app_length;
        if remaining == 0 {
            address
        } else {
            address + (app_length - remaining)
        }
    }

    /// Build exclusion list once at the start of loading
    fn build_exclusion_list(&self) -> ([Option<ExclusionRegion>; 16], usize) {
        let mut exclusions = [None; 16];
        let mut count = 0;
        
        // Bootloader region (0x0 - 0x9000)
        exclusions[count] = Some(ExclusionRegion {
            start: 0x0,
            end: 0x9000,
        });
        count += 1;
        
        if config::CONFIG.debug_load_processes {
            debug!("Exclusion: Bootloader 0x0 - 0x9000");
        }
        
        // Read BDT and add kernel regions
        if let Some((header, kernel_entries)) = read_bdt() {
            let kernel_count = header.kernel_count as usize;
            
            for i in 0..kernel_count.min(MAX_KERNEL_ENTRIES) {
                let entry = &kernel_entries[i];
                if entry.binary_type == BINARY_TYPE_KERNEL && entry.is_valid() {
                    let start = entry.start_address as usize;
                    let end = start + entry.size as usize;
                    
                    exclusions[count] = Some(ExclusionRegion { start, end });
                    count += 1;
                    
                    if config::CONFIG.debug_load_processes {
                        debug!("Exclusion: Kernel 0x{:x} - 0x{:x}", start, end);
                    }
                    
                    if count >= 16 {
                        break;
                    }
                }
            }
        }
        
        (exclusions, count)
    }
    
    /// Check if address is in an exclusion region, return end address if true
    fn check_if_in_exclusion_region(&self, addr: usize) -> Option<usize> {
        let (exclusions, exclusion_count) = self.build_exclusion_list();
        
        for i in 0..exclusion_count {
            if let Some(region) = exclusions[i] {
                if addr >= region.start && addr < region.end {
                    return Some(region.end);
                }
            }
        }
        None
    }

    fn load_and_check(&self) {
        match self.run_mode.get() {
            Some(SequentialProcessLoaderMachineRunMode::RuntimeMode) => {
                // Runtime mode: we already know exactly where the app is
                // Just discover and check the binary at the current flash position
                
                match self.discover_process_binary() {
                    Ok(pb) => {
                        match self.checker.check(pb) {
                            Ok(()) => return,  // Wait for done()
                            Err(_e) => {
                                // Check failed
                                self.state.set(SequentialProcessLoaderMachineState::LoadProcesses);
                                self.deferred_call.set();
                            }
                        }
                    }
                    Err(_e) => {
                        // Binary discovery failed
                        self.state.set(SequentialProcessLoaderMachineState::LoadProcesses);
                        self.deferred_call.set();
                    }
                }
            }
            
            Some(SequentialProcessLoaderMachineRunMode::BootMode) | None => {
                // Scan entire flash, automatically skips exclusion zones
                let mut app_starts = [0usize; 10];
                let mut app_ends = [0usize; 10];
                
                let _ = self.scan_flash_for_process_binaries(
                    self.flash_bank.get(),
                    &mut app_starts,
                    &mut app_ends
                );
                
                // Get current position to track which apps we've already processed
                let current_pos = self.flash.get().as_ptr() as usize;
                
                // Find the first unprocessed app
                for i in 0..app_starts.len() {
                    if app_starts[i] == 0 {
                        break; // No more apps
                    }
                    
                    if app_starts[i] < current_pos {
                        continue; // Already processed this app
                    }
                    
                    // Set flash pointer to this app
                    let flash_bank = self.flash_bank.get();
                    let offset_start = app_starts[i] - flash_bank.as_ptr() as usize;
                    let offset_end = app_ends[i] - flash_bank.as_ptr() as usize;
                    
                    if let Some(app_flash) = flash_bank.get(offset_start..offset_end) {
                        self.flash.set(app_flash);
                        
                        match self.discover_process_binary() {
                            Ok(pb) => {
                                match self.checker.check(pb) {
                                    // Wait for checker async callback
                                    Ok(()) => {return;}
                                    // Check failed, continue to next app
                                    Err(_e) => {continue;}
                                }
                            }
                            Err(_e) => {
                                // Binary discovery failed, continue to next app
                                continue;
                            }
                        }
                    }
                }
                
                // All apps checked, move to loading
                self.state.set(SequentialProcessLoaderMachineState::LoadProcesses);
                self.deferred_call.set();
            }
        }
    }

    /// Try to parse a process binary from flash.
    ///
    /// Returns the process binary object or an error if a valid process
    /// binary could not be extracted.
    fn discover_process_binary(&self) -> Result<ProcessBinary, ProcessBinaryError> {
        let flash = self.flash.get();

        match discover_process_binary(flash) {
            Ok((remaining_flash, pb)) => {
                self.flash.set(remaining_flash);
                Ok(pb)
            }

            Err((remaining_flash, err)) => {
                self.flash.set(remaining_flash);
                Err(err)
            }
        }
    }

    /// Create process objects from the discovered process binaries.
    ///
    /// This verifies that the discovered processes are valid to run.
    fn load_process_objects(&self) -> Result<(), ()> {
        let proc_binaries = self.proc_binaries.take().ok_or(())?;
        let proc_binaries_len = proc_binaries.len();

        // Iterate all process binary entries.
        for i in 0..proc_binaries_len {
            // We are either going to load this process binary or discard it, so
            // we can use `take()` here.
            if let Some(process_binary) = proc_binaries[i].take() {
                // We assume the process can be loaded. This is not the case
                // if there is a conflicting process.
                let mut ok_to_load = true;

                // Start by iterating all other process binaries and seeing
                // if any are in conflict (same AppID with newer version).
                for proc_bin in proc_binaries.iter() {
                    if let Some(other_process_binary) = proc_bin {
                        let blocked =
                            self.is_blocked_from_loading_by(&process_binary, other_process_binary);

                        if blocked {
                            ok_to_load = false;
                            break;
                        }
                    }
                }

                // Go to next ProcessBinary if we cannot load this process.
                if !ok_to_load {
                    continue;
                }

                // Now scan the already loaded processes and make sure this
                // doesn't conflict with any of those. Since those processes
                // are already loaded, we just need to check if this process
                // binary has the same AppID as an already loaded process.
                for proc in self.kernel.get_process_iter() {
                    let blocked = self.is_blocked_from_loading_by_process(&process_binary, proc);
                    if blocked {
                        ok_to_load = false;
                        break;
                    }
                }

                if !ok_to_load {
                    continue;
                }

                // If we get here it is ok to load the process.
                match self.kernel.next_available_process_slot() {
                    Ok((index, slot)) => {
                        // Calculate the ShortId for this new process.
                        let short_app_id = self.policy.map_or(ShortId::LocallyUnique, |policy| {
                            policy.to_short_id(&process_binary)
                        });

                        // Try to create a `Process` object.
                        let load_result = load_process(
                            self.kernel,
                            self.chip,
                            process_binary,
                            self.app_memory.take(),
                            short_app_id,
                            index,
                            self.fault_policy,
                            self.storage_policy,
                        );
                        match load_result {
                            Ok((new_mem, proc)) => {
                                self.app_memory.set(new_mem);
                                match proc {
                                    Some(p) => {
                                        if config::CONFIG.debug_load_processes {
                                            debug!(
                                                "Loading: Loaded process {}",
                                                p.get_process_name()
                                            )
                                        }

                                        // Store the `ProcessStandard` object in the `PROCESSES`
                                        // array.
                                        slot.set(p);
                                        // Notify the client the process was loaded
                                        // successfully.
                                        self.get_current_client().map(|client| {
                                            client.process_loaded(Ok(()));
                                        });
                                    }
                                    None => {
                                        if config::CONFIG.debug_load_processes {
                                            debug!("No process loaded.");
                                        }
                                    }
                                }
                            }
                            Err((new_mem, err)) => {
                                self.app_memory.set(new_mem);
                                if config::CONFIG.debug_load_processes {
                                    debug!("Could not load process: {:?}.", err);
                                }
                                self.get_current_client().map(|client| {
                                    client.process_loaded(Err(err));
                                });
                            }
                        }
                    }
                    Err(()) => {
                        // Nowhere to store the process.
                        self.get_current_client().map(|client| {
                            client.process_loaded(Err(ProcessLoadError::NoProcessSlot));
                        });
                    }
                }
            }
        }
        self.proc_binaries.put(proc_binaries);

        // We have iterated all discovered `ProcessBinary`s and loaded what we
        // could so now we can signal that process loading is finished.
        self.get_current_client().map(|client| {
            client.process_loading_finished();
        });

        self.state.clear();
        Ok(())
    }

    /// Check if `pb1` is blocked from running by `pb2`.
    ///
    /// `pb2` blocks `pb1` if:
    ///
    /// - They both have the same AppID or they both have the same ShortId, and
    /// - `pb2` has a higher version number.
    fn is_blocked_from_loading_by(&self, pb1: &ProcessBinary, pb2: &ProcessBinary) -> bool {
        let same_app_id = self
            .policy
            .map_or(false, |policy| !policy.different_identifier(pb1, pb2));
        let same_short_app_id = self.policy.map_or(false, |policy| {
            policy.to_short_id(pb1) == policy.to_short_id(pb2)
        });
        let other_newer = pb2.header.get_binary_version() > pb1.header.get_binary_version();

        let blocks = (same_app_id || same_short_app_id) && other_newer;

        if config::CONFIG.debug_process_credentials {
            debug!(
                "Loading: ProcessBinary {}({:#02x}) does{} block {}({:#02x})",
                pb2.header.get_package_name().unwrap_or(""),
                pb2.flash.as_ptr() as usize,
                if blocks { "" } else { " not" },
                pb1.header.get_package_name().unwrap_or(""),
                pb1.flash.as_ptr() as usize,
            );
        }

        blocks
    }

    /// Check if `pb` is blocked from running by `process`.
    ///
    /// `process` blocks `pb` if:
    ///
    /// - They both have the same AppID, or
    /// - They both have the same ShortId
    ///
    /// Since `process` is already loaded, we only have to enforce the AppID and
    /// ShortId uniqueness guarantees.
    fn is_blocked_from_loading_by_process(
        &self,
        pb: &ProcessBinary,
        process: &dyn Process,
    ) -> bool {
        let same_app_id = self.policy.map_or(false, |policy| {
            !policy.different_identifier_process(pb, process)
        });
        let same_short_app_id = self.policy.map_or(false, |policy| {
            policy.to_short_id(pb) == process.short_app_id()
        });

        let blocks = same_app_id || same_short_app_id;

        if config::CONFIG.debug_process_credentials {
            debug!(
                "Loading: Process {}({:#02x}) does{} block {}({:#02x})",
                process.get_process_name(),
                process.get_addresses().flash_start,
                if blocks { "" } else { " not" },
                pb.header.get_package_name().unwrap_or(""),
                pb.flash.as_ptr() as usize,
            );
        }

        blocks
    }

    ////////////////////////////////////////////////////////////////////////////////
    // DYNAMIC PROCESS LOADING HELPERS
    ////////////////////////////////////////////////////////////////////////////////

    /// Scan the entire flash to populate lists of existing binaries addresses.
    fn scan_flash_for_process_binaries(
        &self,
        flash: &'static [u8],
        process_binaries_start_addresses: &mut [usize],
        process_binaries_end_addresses: &mut [usize],
    ) -> Result<(), ()> {
        fn inner_function(
            flash: &'static [u8],
            process_binaries_start_addresses: &mut [usize],
            process_binaries_end_addresses: &mut [usize],
            check_exclusion: impl Fn(usize) -> Option<usize>,
        ) -> Result<(), ProcessBinaryError> {
            let flash_end = flash.as_ptr() as usize + flash.len() - 1;
            let flash_start = flash.as_ptr() as usize;
            let mut addresses = flash_start;
            let mut index: usize = 0;
            const PAGE_SIZE: usize = 0x1000;

            while addresses < flash_end {
                // Check if we're in exclusion zone
                if let Some(exclusion_end) = check_exclusion(addresses) {
                    // Align to next page after exclusion
                    addresses = ((exclusion_end + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
                    continue;
                }

                let flash_offset = addresses - flash_start;

                let test_header_slice = flash
                    .get(flash_offset..flash_offset + 8)
                    .ok_or(ProcessBinaryError::NotEnoughFlash)?;

                let header = test_header_slice
                    .try_into()
                    .or(Err(ProcessBinaryError::NotEnoughFlash))?;

                let (_version, header_length, app_length) =
                    match tock_tbf::parse::parse_tbf_header_lengths(header) {
                        Ok((v, hl, el)) => (v, hl, el),
                        Err(tock_tbf::types::InitialTbfParseError::InvalidHeader(app_length)) => {
                            (0, 0, app_length)
                        }
                        // Err(tock_tbf::types::InitialTbfParseError::UnableToParse) => {
                        //     return Ok(());
                        // }
                        Err(tock_tbf::types::InitialTbfParseError::UnableToParse) => {
                            // Skip to next page and continue scanning
                            addresses = ((addresses + PAGE_SIZE) / PAGE_SIZE) * PAGE_SIZE;
                            continue;
                        }
                    };

                let app_flash = flash
                    .get(flash_offset..flash_offset + app_length as usize)
                    .ok_or(ProcessBinaryError::NotEnoughFlash)?;

                let app_header = flash
                    .get(flash_offset..flash_offset + header_length as usize)
                    .ok_or(ProcessBinaryError::NotEnoughFlash)?;

                let remaining_flash = flash
                    .get(flash_offset + app_flash.len()..)
                    .ok_or(ProcessBinaryError::NotEnoughFlash)?;

                let remaining_header = app_header
                    .get(16..)
                    .ok_or(ProcessBinaryError::NotEnoughFlash)?;

                if remaining_header.len() == 0 {
                    // Padding
                } else {
                    // This is an app binary
                    process_binaries_start_addresses[index] = app_flash.as_ptr() as usize;
                    process_binaries_end_addresses[index] =
                        app_flash.as_ptr() as usize + app_length as usize;

                    if config::CONFIG.debug_load_processes {
                        debug!(
                            "[Metadata] Process binary at {:#010x}",
                            process_binaries_start_addresses[index]
                        );
                    }
                    index += 1;
                    if index > process_binaries_start_addresses.len() - 1 {
                        return Err(ProcessBinaryError::NotEnoughFlash);
                    }
                }
                addresses = remaining_flash.as_ptr() as usize;
            }

            Ok(())
        }

        inner_function(
            flash,
            process_binaries_start_addresses,
            process_binaries_end_addresses,
            |addr| self.check_if_in_exclusion_region(addr),
        )
        .or(Err(()))
    }

    /// Function to compute the address for a new app with size `app_size`.
    fn compute_new_process_binary_address(
        &self,
        app_size: usize,
        process_binaries_start_addresses: &mut [usize],
        process_binaries_end_addresses: &mut [usize],
    ) -> Option<usize> {
        
        // Collect all occupied regions (exclusions + apps)
        let mut occupied_regions: [(usize, usize); 26] = [(0, 0); 26]; // 16 exclusions + 10 apps
        let mut region_count = 0;
        
        // Add exclusion regions (bootloader + kernels)
        let (exclusions, exclusion_count) = self.build_exclusion_list();
        for i in 0..exclusion_count {
            if let Some(region) = exclusions[i] {
                occupied_regions[region_count] = (region.start, region.end);
                region_count += 1;
            }
        }
        
        // Add existing app regions
        for i in 0..process_binaries_start_addresses.len() {
            if process_binaries_start_addresses[i] != 0 {
                occupied_regions[region_count] = (
                    process_binaries_start_addresses[i],
                    process_binaries_end_addresses[i]
                );
                region_count += 1;
            }
        }
        
        // Sort regions by start address
        for i in 0..region_count {
            for j in i+1..region_count {
                if occupied_regions[j].0 < occupied_regions[i].0 {
                    let temp = occupied_regions[i];
                    occupied_regions[i] = occupied_regions[j];
                    occupied_regions[j] = temp;
                }
            }
        }
        
        // Find first gap that fits the new app
        let flash_bank = self.flash_bank.get();
        let flash_start = flash_bank.as_ptr() as usize;
        
        // Check gap before first region
        if region_count > 0 {
            let gap_start = flash_start;
            let gap_end = occupied_regions[0].0;
            
            if gap_end > gap_start {
                let potential_address = self.find_next_cortex_m_aligned_address(gap_start, app_size);
                if potential_address + app_size <= gap_end {
                    return Some(potential_address);
                }
            }
        }
        
        // Check gaps between consecutive regions
        for i in 0..region_count.saturating_sub(1) {
            let gap_start = occupied_regions[i].1;
            let gap_end = occupied_regions[i+1].0;
            
            if gap_end > gap_start {
                let potential_address = self.find_next_cortex_m_aligned_address(gap_start, app_size);
                if potential_address + app_size <= gap_end {
                    return Some(potential_address);
                }
            }
        }
        
        // Check gap after last region
        if region_count > 0 {
            let gap_start = occupied_regions[region_count - 1].1;
            let potential_address = self.find_next_cortex_m_aligned_address(gap_start, app_size);
            return Some(potential_address);
        }

        None
    }

    /// This function checks if there is a need to pad either before or after
    /// the new app to preserve the linked list.
    ///
    /// When do we pad?
    ///
    /// 1. When there is a binary  located in flash after the new app but
    ///    not immediately after, we need to add padding between the new
    ///    app and the existing app.
    /// 2. Due to MPU alignment, the new app may be similarly placed not
    ///    immediately after an existing process, in that case, we need to add
    ///    padding between the previous app and the new app.
    /// 3. If both the above conditions are met, we add both a prepadding and a
    ///    postpadding.
    /// 4. If either of these conditions are not met, we don't pad.
    ///
    /// Change checks against process binaries instead of processes?
    fn compute_padding_requirement_and_neighbors(
        &self,
        new_app_start_address: usize,
        app_length: usize,
        process_binaries_start_addresses: &[usize],
        process_binaries_end_addresses: &[usize],
    ) -> (PaddingRequirement, usize, usize) {
        // The end address of our newly loaded application.
        let new_app_end_address = new_app_start_address + app_length;
        // To store the address until which we need to write the padding app.
        let mut next_app_start_addr = 0;
        // To store the address from which we need to write the padding app.
        let mut previous_app_end_addr = 0;
        let mut padding_requirement: PaddingRequirement = PaddingRequirement::None;

        // We compute the closest neighbor to our app such that:
        //
        // 1. If the new app is placed in between two existing binaries, we
        //    compute the closest located binaries.
        // 2. Once we compute these values, we determine if we need to write a
        //    pre pad header, or a post pad header, or both.
        // 3. If there are no apps after ours in the process binary array, we don't
        //    do anything.

        // Postpad requirement.
        if let Some(next_closest_neighbor) = process_binaries_start_addresses
            .iter()
            .filter(|&&x| x > new_app_end_address - 1)
            .min()
        {
            // We found the next closest app in flash.
            next_app_start_addr = *next_closest_neighbor;
            if next_app_start_addr != 0 {
                padding_requirement = PaddingRequirement::PostPad;
            }
        } else {
            if config::CONFIG.debug_load_processes {
                debug!("No App Found after the new app so not adding post padding.");
            }
        }

        // Prepad requirement.
        if let Some(previous_closest_neighbor) = process_binaries_end_addresses
            .iter()
            .filter(|&&x| x < new_app_start_address + 1)
            .max()
        {
            // We found the previous closest app in flash.
            previous_app_end_addr = *previous_closest_neighbor;
            if new_app_start_address - previous_app_end_addr != 0 {
                if padding_requirement == PaddingRequirement::PostPad {
                    padding_requirement = PaddingRequirement::PreAndPostPad;
                } else {
                    padding_requirement = PaddingRequirement::PrePad;
                }
            }
        } else {
            if config::CONFIG.debug_load_processes {
                debug!("No Previous App Found, so not padding before the new app.");
            }
        }
        (
            padding_requirement,
            previous_app_end_addr,
            next_app_start_addr,
        )
    }

    /// This function scans flash, checks for, and returns an address that follows alignment rules given
    /// an app size of `new_app_size`.
    fn check_flash_for_valid_address(
        &self,
        new_app_size: usize,
        pb_start_address: &mut [usize],
        pb_end_address: &mut [usize],
    ) -> Result<usize, ProcessBinaryError> {
        let total_flash = self.flash_bank.get();
        let total_flash_start = total_flash.as_ptr() as usize;
        let total_flash_end = total_flash_start + total_flash.len() - 1;

        match self.scan_flash_for_process_binaries(total_flash, pb_start_address, pb_end_address) {
            Ok(()) => {
                if config::CONFIG.debug_load_processes {
                    debug!("Successfully scanned flash");
                }
                // let new_app_address = match self.compute_new_process_binary_address(
                //     new_app_size,
                //     pb_start_address,
                //     pb_end_address,
                // );
                let new_app_address = self.compute_new_process_binary_address(
                    new_app_size,
                    pb_start_address,
                    pb_end_address,
                ).ok_or(ProcessBinaryError::NotEnoughFlash)?;
                if new_app_address + new_app_size - 1 > total_flash_end {
                    Err(ProcessBinaryError::NotEnoughFlash)
                } else {
                    Ok(new_app_address)
                }
            }
            Err(()) => Err(ProcessBinaryError::NotEnoughFlash),
        }
    }

    /// Function to check if the object with address `offset` of size `length` lies
    /// within flash bounds.
    pub fn check_if_within_flash_bounds(&self, offset: usize, length: usize) -> bool {
        let flash = self.flash_bank.get();
        let flash_end = flash.as_ptr() as usize + flash.len() - 1;

        (flash_end - offset) >= length
    }

    /// Function to compute an available address for the new application binary.
    pub fn check_flash_for_new_address(
        &self,
        new_app_size: usize,
    ) -> Result<(usize, PaddingRequirement, usize, usize), ProcessBinaryError> {
        const MAX_PROCS: usize = 10;
        let mut pb_start_address: [usize; MAX_PROCS] = [0; MAX_PROCS];
        let mut pb_end_address: [usize; MAX_PROCS] = [0; MAX_PROCS];
        match self.check_flash_for_valid_address(
            new_app_size,
            &mut pb_start_address,
            &mut pb_end_address,
        ) {
            Ok(app_address) => {
                let (pr, prev_app_addr, next_app_addr) = self
                    .compute_padding_requirement_and_neighbors(
                        app_address,
                        new_app_size,
                        &pb_start_address,
                        &pb_end_address,
                    );
                let (padding_requirement, previous_app_end_addr, next_app_start_addr) =
                    (pr, prev_app_addr, next_app_addr);
                Ok((
                    app_address,
                    padding_requirement,
                    previous_app_end_addr,
                    next_app_start_addr,
                ))
            }
            Err(e) => Err(e),
        }
    }

    /// Function to check if the app binary at address `app_address` is valid.
    fn check_new_binary_validity(&self, app_address: usize) -> bool {
        let flash = self.flash_bank.get();
        // Pass the first eight bytes of the tbfheader to parse out the
        // length of the tbf header and app. We then use those values to see
        // if we have enough flash remaining to parse the remainder of the
        // header.
        let binary_header = match flash.get(app_address..app_address + 8) {
            Some(slice) if slice.len() == 8 => slice,
            _ => return false, // Ensure exactly 8 bytes are available
        };

        let binary_header_array: &[u8; 8] = match binary_header.try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };

        match tock_tbf::parse::parse_tbf_header_lengths(binary_header_array) {
            Ok((_version, _header_length, _entry_length)) => true,
            Err(tock_tbf::types::InitialTbfParseError::InvalidHeader(_entry_length)) => false,
            Err(tock_tbf::types::InitialTbfParseError::UnableToParse) => false,
        }
    }

    /// Function to start loading the new application at address `app_address` with size
    /// `app_size`.
    pub fn load_new_process_binary(
        &self,
        app_address: usize,
        app_size: usize,
    ) -> Result<(), ProcessLoadError> {
        let flash = self.flash_bank.get();
        let process_address = app_address - flash.as_ptr() as usize;
        let process_flash = flash.get(process_address..process_address + app_size);
        let result = self.check_new_binary_validity(process_address);
        match result {
            true => {
                if config::CONFIG.debug_load_processes {
                    debug!(
                        "process address: {:#0x}, with a size: {:#00x}", 
                        process_address, 
                        app_size
                    );
                }
                if let Some(flash) = process_flash {
                    self.flash.set(flash);
                } else {
                    return Err(ProcessLoadError::BinaryError(
                        ProcessBinaryError::TbfHeaderNotFound,
                    ));
                }

                self.state
                    .set(SequentialProcessLoaderMachineState::DiscoverProcessBinaries);

                self.run_mode
                    .set(SequentialProcessLoaderMachineRunMode::RuntimeMode);
                // Start an asynchronous flow so we can issue a callback on error.
                self.deferred_call.set();

                Ok(())
            }
            false => Err(ProcessLoadError::BinaryError(
                ProcessBinaryError::TbfHeaderNotFound,
            )),
        }
    }
}

impl<'a, C: Chip, D: ProcessStandardDebug> ProcessLoadingAsync<'a>
    for SequentialProcessLoaderMachine<'a, C, D>
{
    fn set_client(&self, client: &'a dyn ProcessLoadingAsyncClient) {
        self.boot_client.set(client);
    }

    fn set_policy(&self, policy: &'a dyn AppIdPolicy) {
        self.policy.replace(policy);
    }

    fn start(&self) {
        self.state
            .set(SequentialProcessLoaderMachineState::DiscoverProcessBinaries);
        self.run_mode
            .set(SequentialProcessLoaderMachineRunMode::BootMode);
        // Start an asynchronous flow so we can issue a callback on error.
        self.deferred_call.set();
    }
}

impl<C: Chip, D: ProcessStandardDebug> DeferredCallClient
    for SequentialProcessLoaderMachine<'_, C, D>
{
    fn handle_deferred_call(&self) {
        // We use deferred calls to start the operation in the async loop.
        // debug!("=== handle_deferred_call, state={:?} ===", self.state.get());
        match self.state.get() {
            Some(SequentialProcessLoaderMachineState::DiscoverProcessBinaries) => {
                self.load_and_check();
            }
            Some(SequentialProcessLoaderMachineState::LoadProcesses) => {
                let ret = self.load_process_objects();
                match ret {
                    Ok(()) => {}
                    Err(()) => {
                        // If this failed for some reason, we still need to
                        // signal that process loading has finished.
                        self.get_current_client().map(|client| {
                            client.process_loading_finished();
                        });
                    }
                }
            }
            None => {}
        }
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

impl<C: Chip, D: ProcessStandardDebug> crate::process_checker::ProcessCheckerMachineClient
    for SequentialProcessLoaderMachine<'_, C, D>
{
    fn done(
        &self,
        process_binary: ProcessBinary,
        result: Result<Option<AcceptedCredential>, crate::process_checker::ProcessCheckError>,
    ) {
        // Check if this process was approved by the checker.
        match result {
            Ok(optional_credential) => {
                if config::CONFIG.debug_load_processes {
                    debug!(
                        "Loading: Check succeeded for process {}",
                        process_binary.header.get_package_name().unwrap_or("")
                    );
                }
                // Save the checked process binary now that we know it is valid.
                match self.find_open_process_binary_slot() {
                    Some(index) => {
                        self.proc_binaries.map(|proc_binaries| {
                            process_binary.credential.insert(optional_credential);
                            proc_binaries[index] = Some(process_binary);
                        });
                    }
                    None => {
                        self.get_current_client().map(|client| {
                            client.process_loaded(Err(ProcessLoadError::NoProcessSlot));
                        });
                    }
                }
            }
            Err(e) => {
                if config::CONFIG.debug_load_processes {
                    debug!(
                        "Loading: Process {} check failed {:?}",
                        process_binary.header.get_package_name().unwrap_or(""),
                        e
                    );
                }
                // Signal error and call try next
                self.get_current_client().map(|client| {
                    client.process_loaded(Err(ProcessLoadError::CheckError(e)));
                });
            }
        }
        self.deferred_call.set();
    }
}
