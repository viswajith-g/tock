//! Helper functions related to Tock processes by OTA_app.

use core::cell::Cell;
use core::cmp;

// use crate::capabilities::MemoryAllocationCapability;
use crate::config;
use crate::create_capability;
use crate::debug;
// use crate::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use crate::kernel::Kernel;
use crate::platform::chip::Chip;
use crate::process::ProcessId;
use crate::process::{self, Process};
use crate::process_loading::ProcessLoadError;
use crate::process_policies::ProcessFaultPolicy;
use crate::process_standard::ProcessStandard;
// use crate::syscall_driver::{CommandReturn, SyscallDriver};
use crate::utilities::cells::{MapCell, OptionalCell, TakeCell};
use crate::ErrorCode;
use crate::hil::nonvolatile_storage::{NonvolatileStorage, NonvolatileStorageClient};
// use crate::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
// use crate::hil::process_load_utilities::{DynamicProcessLoadingHasClient, DynamicProcessLoadingClient};

// pub const DRIVER_NUM: usize = 0x10002;  //to create grant
pub const BUF_LEN: usize = 512;    
const TBF_HEADER_LENGTH: usize = 16;


/// IDs for subscribed upcalls.
// mod upcall {
//     /// Read done callback.
//     pub const READ_DONE: usize = 0;
//     /// Write done callback.
//     pub const WRITE_DONE: usize = 1;
//     /// Number of upcalls.
//     pub const COUNT: u8 = 2;
// }

// /// Ids for read-only allow buffers
// mod ro_allow {
//     /// Setup a buffer to write bytes to the nonvolatile storage.
//     pub const WRITE: usize = 0;
//     /// The number of allow buffers the kernel stores for this grant
//     pub const COUNT: u8 = 1;
// }

// /// Ids for read-write allow buffers
// mod rw_allow {
//     /// Setup a buffer to read from the nonvolatile storage into.
//     pub const READ: usize = 0;
//     /// The number of allow buffers the kernel stores for this grant
//     pub const COUNT: u8 = 1;
// }
         
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum NonvolatileCommand {
    UserspaceRead,
    UserspaceWrite,
}

// #[derive(Clone, Copy)]
// pub enum NonvolatileUser {
//     App { processid: ProcessId },
// }

// pub struct App {
//     // pending_command: bool,
//     command: NonvolatileCommand,
//     offset: usize,
//     length: usize,
//     new_addr: usize,
//     new_len: usize,
// }

// impl Default for App {
//     fn default() -> App {
//         App {
//             // pending_command: false,
//             command: NonvolatileCommand::UserspaceRead,
//             offset: 0,
//             length: 0,
//             new_addr: 0,
//             new_len: 0,
//         }
//     }
// }


struct NewApp{
    // App size requested by userland ota app
    size: usize,
    // start_addr points the start address where the new app will be loaded
    start_addr: usize,
}


/// This interface supports loading processes at runtime.
pub trait DynamicProcessLoading {
    /// Call to request loading a new process.
    ///
    /// This informs the kernel we want to load a process and the size of the entire process binary.
    /// The kernel will try to find a suitable location in flash to store said process.
    ///
    /// Return value:
    /// - `Ok((start_address, length))`: If there is a place to load the
    ///   process, the function will return `Ok()` with the address to start at
    ///   and the size of the region to store the process.
    /// - `Err(ErrorCode)`: If there is nowhere to store the process a suitable
    ///   `ErrorCode` will be returned.
    fn setup(&self, app_length: usize) -> Result<(usize, usize), ErrorCode>;

    /// Instruct the kernel to write data to the flash
    ///
    ///This is used to write both userland apps and padding apps
    fn write_app_data(&self, flag: bool, buffer: &'static mut [u8], offset: usize, app_size: usize, processid: ProcessId) -> Result<(), ErrorCode>;

    /// Instruct the kernel to load and execute the process.
    ///
    /// This tells the kernel to try to actually execute the new process that
    /// was just installed in flash from the preceding `write()` call.
    fn load(&self) -> Result<(), ErrorCode>;


    /// Sets a client for the DynamicProcessLoading Object
    ///
    /// When the client operation is done, it calls the app_data_write_done() function
    fn set_client(&self, client: &'static dyn DynamicProcessLoadingClient);
}

pub trait DynamicProcessLoadingClient{
    fn app_data_write_done(&self, buffer: &'static mut [u8], length: usize);
}

pub struct DynamicProcessLoader<'a, C: 'static + Chip> {
    kernel: &'static Kernel,
    chip: &'static C,
    fault_policy: &'static dyn ProcessFaultPolicy,
    procs: MapCell<&'static mut [Option<&'static dyn process::Process>]>,
    flash: Cell<&'static [u8]>,
    app_memory: OptionalCell<&'static mut [u8]>,
    flash_start: Cell<usize>,
    flash_end: Cell<usize>,
    new_process_flash: OptionalCell<&'static [u8]>,
    // current_user: OptionalCell<NonvolatileUser>,
    // apps: Grant<
    //     App,
    //     UpcallCount<{ upcall::COUNT }>,
    //     AllowRoCount<{ ro_allow::COUNT }>,
    //     AllowRwCount<{ rw_allow::COUNT }>,
    // >, 
    driver: &'a dyn NonvolatileStorage<'a>,
    buffer: TakeCell<'static, [u8]>,
    new_app_start_addr: Cell<usize>,
    new_app_length: Cell<usize>,
    client: OptionalCell<&'static dyn DynamicProcessLoadingClient>,
}

impl<'a, C: 'static + Chip> DynamicProcessLoader<'a, C> {
    pub fn new(
        processes: &'static mut [Option<&'static dyn process::Process>],
        kernel: &'static Kernel,
        chip: &'static C,
        flash: &'static [u8],
        fault_policy: &'static dyn ProcessFaultPolicy,
        // apps: Grant<
        //     App,
        //     UpcallCount<{ upcall::COUNT }>,
        //     AllowRoCount<{ ro_allow::COUNT }>,
        //     AllowRwCount<{ rw_allow::COUNT }>,
        // >, 
        driver: &'a dyn NonvolatileStorage<'a>,
        buffer: &'static mut [u8],
    ) -> Self {
        Self {
            procs: MapCell::new(processes),
            kernel,
            chip,
            flash: Cell::new(flash),
            app_memory: OptionalCell::empty(),
            flash_start: Cell::new(0),
            flash_end: Cell::new(0),
            fault_policy,
            new_process_flash: OptionalCell::empty(),
            // current_user: OptionalCell::empty(),
            // apps: apps,
            driver: driver,
            buffer: TakeCell::new(buffer),
            new_app_start_addr: Cell::new(0),
            new_app_length: Cell::new(0),
            client: OptionalCell::empty(),
        }
    }

    // Needs to be set separately, or breaks grants allocation
    pub fn flash_and_memory(
        &self,
        app_memory: &'static mut [u8],
        flash_start: usize,
        flash_end: usize,
    ){
        self.app_memory.set(app_memory);
        self.flash_start.set(flash_start);
        self.flash_end.set(flash_end);
    }

    fn find_open_process_slot(&self) -> Option<usize> {
        self.procs.map_or(None, |procs| {
            for (i, p) in procs.iter().enumerate() {
                if p.is_none() {
                    return Some(i);
                }
            }
            None
        })
    }

    /******************************************* NVM Stuff **********************************************************/
    
    // Check so see if we are doing something. If not, go ahead and do this
    // command. If so, this is queued and will be run when the pending
    // command completes.
    fn enqueue_command(
        &self,
        padding_flag: bool,
        command: NonvolatileCommand,
        user_buffer: &'static mut [u8],
        offset: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {
        // Do bounds check.
        if !padding_flag {                  //perform this bounds check if it is not a padding header because it comes from the user application
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
        }

        debug!("userspace call driver about to be called");
        self.userspace_call_driver(padding_flag, command, user_buffer, offset, length)
    }

    fn userspace_call_driver(
        &self,
        padding_flag: bool,
        command: NonvolatileCommand,
        user_buffer: &'static mut [u8],
        offset: usize,
        length: usize,
        // new_app_address: usize,
    ) -> Result<(), ErrorCode> {
        // Calculate where we want to actually read from in the physical
        // storage.
        let mut physical_address = 0;
        if !padding_flag{
            physical_address = offset + self.new_app_start_addr.get();
        }
        else{
            physical_address = offset;
        }

        debug!("physical address for write: {}\n", physical_address);
        let active_len = cmp::min(length, user_buffer.len());
                debug!("active length: {}\n", active_len);

                match command {
                    NonvolatileCommand::UserspaceRead => {
                        self.driver.read(user_buffer, physical_address, active_len)
                    }
                    NonvolatileCommand::UserspaceWrite => {
                        debug!("writing to flash\n");
                        self.driver.write(user_buffer, physical_address, active_len)
                    }
                    _ => Err(ErrorCode::FAIL),
                }
    }

 /******************************************* Process Load Stuff **********************************************************/

    fn check_for_padding_app(&self, new_app: &mut NewApp) -> Result<bool, ProcessLoadError> {
        //We only need tbf header information to get the size of app which is already loaded
        let header_info = unsafe { core::slice::from_raw_parts(new_app.start_addr as *const u8, 8) };

        // let header_info = self.flash.get().get(start_addr..start_addr+8);

        let test_header_slice = match header_info.get(0..8) {
            Some(s) => s,
            None => {
                // Not enough flash to test for another app. This just means
                // We are at the end of flash (0x80000). => This case is Error!
                // But we can't reach out to here in this while statement!
                return Err(ProcessLoadError::InternalError);
            }
        };

        // Pass the first eight bytes to tbfheader to parse out the length of
        // the tbf header and app. We then use those values to see if we have
        // enough flash remaining to parse the remainder of the header.
        let (version, header_length, _entry_length) =
            match tock_tbf::parse::parse_tbf_header_lengths(
                test_header_slice
                    .try_into()
                    .or(Err(ProcessLoadError::InternalError))?,
            ) {
                Ok((v, hl, el)) => (v, hl, el),
                Err(tock_tbf::types::InitialTbfParseError::InvalidHeader(_entry_length)) => {
                    // If we could not parse the header, then we want to skip over
                    // this app and look for the next one.
                    return Err(ProcessLoadError::InternalError);
                }
                Err(tock_tbf::types::InitialTbfParseError::UnableToParse) => {
                    // Since Tock apps use a linked list, it is very possible the
                    // header we started to parse is intentionally invalid to signal
                    // the end of apps. This is ok and just means we have finished
                    // loading apps.
                    return Ok(false);
                }
            };

        //If a padding app is exist at the start address satisfying MPU rules, we load the new app from here!
        let header_flash =
            unsafe { core::slice::from_raw_parts(new_app.start_addr as *const u8, header_length as usize) };

        // let header_flash =  self.flash.get().get(new_app.start_addr..header_length as usize);

        let tbf_header = tock_tbf::parse::parse_tbf_header(header_flash, version)?;

        // If this isn't an app (i.e. it is padding)
        if !tbf_header.is_app() {
            return Ok(true);
        }

        return Ok(false);
    }

    fn check_for_empty_flash_region(&self, new_app: &mut NewApp) -> Result<(bool, usize), ProcessLoadError> {
        //We only need tbf header information to get the size of app which is already loaded
        let header_info = unsafe { core::slice::from_raw_parts(new_app.start_addr as *const u8, 8) };

        let test_header_slice = match header_info.get(0..8) {
            Some(s) => s,
            None => {
                // Not enough flash to test for another app. This just means
                // We are at the end of flash (0x80000). => This case is Error!
                // But we can't reach out to here in this while statement!
                return Err(ProcessLoadError::NotEnoughFlash);
            }
        };

        let (_version, _header_length, entry_length) =
            match tock_tbf::parse::parse_tbf_header_lengths(
                test_header_slice
                    .try_into()
                    .or(Err(ProcessLoadError::InternalError))?,
            ) {
                Ok((v, hl, el)) => (v, hl, el),
                Err(tock_tbf::types::InitialTbfParseError::InvalidHeader(_entry_length)) => {
                    // If we could not parse the header, then we want to skip over
                    // this app and look for the next one.
                    return Err(ProcessLoadError::InternalError);
                }
                Err(tock_tbf::types::InitialTbfParseError::UnableToParse) => {
                    // Since Tock apps use a linked list, it is very possible the
                    // header we started to parse is intentionally invalid to signal
                    // the end of apps. This is ok and just means we have finished
                    // loading apps.
                    // This case points to a viable start_addr satisfying MPU rules for an new app
                    return Ok((true, 0));
                }
            };
        return Ok((false, entry_length as usize)); // this means there is something here, and we need to check if it is a remnant app
    }

    // check if our new app overlaps with existing apps
    fn check_overlap_region(
        &self,
        new_app: &mut NewApp,
    ) -> Result<(), (usize, ProcessLoadError)>{
        
        let new_process_count = self.find_open_process_slot().unwrap_or_default();  // should never default because we have at least the OTA helper app running
        let new_process_start_address = new_app.start_addr;
        let new_process_end_address = new_app.start_addr + new_app.size - 1;

        self.procs.map(|procs| {
            for (proc_index, value) in procs.iter().enumerate(){
                while proc_index < new_process_count{

                    let process_start_address = value.unwrap().get_addresses().flash_start;
                    let process_end_address = value.unwrap().get_addresses().flash_end;

                    //debug!("process_start_address, process_end_address, {:#010X} {:#010X}", process_start_address, process_end_address);
                    //debug!("new_process_start_address, new_process_end_address, {:#010X} {:#010X}", new_process_start_address, new_process_end_address);

                    if new_process_end_address >= process_start_address && new_process_end_address <= process_end_address          
                    {
                        /* Case 1
                        *              _________________          _______________           _________________
                        *  ___________|__               |        |              _|_________|__               |
                        * |           |  |              |        |             | |         |  |              |
                        * |   new app |  |  app2        |   or   |   app1      | | new app |  |  app2        | 
                        * |___________|__|              |        |             |_|_________|__|              |
                        *             |_________________|        |_______________|         |_________________|
                        * 
                        * ^...........^                                           ^........^
                        * In this case, we discard this region and try to find another start address from the end address + 1 of app2
                        */
                        return Err((process_end_address + 1, ProcessLoadError::NotEnoughFlash));
                    }

                    else if new_process_start_address >= process_start_address && new_process_start_address <= process_end_address
                    {
                        /* Case 2
                        *              _________________
                        *  ___________|__               |    _______________
                        * |           |  |              |   |               |
                        * |   app2    |  |  new app     |   |     app3      |         
                        * |___________|__|              |   |_______________|
                        *             |_________________|
                        * 
                        *                 ^
                        *                 | In this case, the start address of new app is replaced by 'the end address + 1' of app2, 
                        *                   and we try to find another start address from the end address + 1 of app2 and recheck for 
                        *                   the previous condition
                        */
                        return Err((process_end_address + 1, ProcessLoadError::NotEnoughFlash));
                    }
                }
            }
            return Ok(());
        });   
        return Ok(());
    }

    fn find_next_available_address(&self,
        new_app: &mut NewApp) -> Result<(), ProcessLoadError>{

        while new_app.start_addr < self.flash_end.get(){
            let mut is_padding_app: bool = false;
            let mut is_empty_region: bool = false;
            let mut is_remnant_region: bool = true;

            //TODO: Check if it is a newer version of an existing app. 
            // We should then potentially erase the old app information and flash the new app before loading it.

            let padding_result = self.check_for_padding_app(new_app);     //check if there is a padding app in that space
            match padding_result{
                Ok(padding_app)=>{
                    if padding_app == true{
                        is_padding_app = true;
                    }
                }
                Err(_e) => {
                    return Err(ProcessLoadError::InternalError);
                }
            }

            let empty_result = self.check_for_empty_flash_region(new_app);       //check if the flash region is empty
                match empty_result{
                    Ok((empty_space, size))=>{
                        if empty_space == true{
                            is_empty_region = true;
                        }
                        else{
                            let new_process_count = self.find_open_process_slot().unwrap_or_default();  // should never default because we have at least the OTA helper app running
                            // check if there is a remnant app in that space
                            self.procs.map(|procs| {
                                for (proc_index, value) in procs.iter().enumerate(){
                                    while proc_index < new_process_count{
                                    {
                                        if new_app.start_addr == value.unwrap().get_addresses().flash_start
                                            {
                                            is_remnant_region = false;  //indicates there is an active process whose binary is loaded here
                                            break;
                                            }
                                    }
                                }
                            }
                            });

                            // Because there is an app which is also an active process, we move to the next address 
                            if is_remnant_region == false
                            {   
                                // Jump to the maximum length based on power of 2
                                new_app.start_addr += cmp::max(new_app.size, size);
                            }
                        }
                    }
                    Err(_e) => {
                        return Err(ProcessLoadError::InternalError);
                    }
                }
            
            if is_padding_app == true || is_empty_region == true{
                let address_validity_check = self.check_overlap_region(new_app);

                    match address_validity_check{
                        Ok(()) => {
                            return Ok(());
                        }
                        Err((new_start_addr, _e)) => {
                            // We try again from the end of the overlapping app
                            new_app.start_addr = new_start_addr;
                        }
                    }
                    return Ok(());
            }
        }
        return Err(ProcessLoadError::NotEnoughFlash);
    }

    fn write_padding_app(&self, 
        current_process_end_addr: usize, 
        padding_app_length: usize,
        version: u16,
        padding_header_len: usize,)
        -> Result<(), ErrorCode>{

        // let padding_length:usize = padding_app_length;

        //let mut padding_array: [u8;padding_length] = [0xff; padding_length];
        self.buffer.map(|buffer|{
            // let mut padding_array: [u8;TBF_HEADER_LENGTH] = [0xff; TBF_HEADER_LENGTH];
            // let padding_buffer: &'static mut [u8] = &mut padding_array;
            // write the header into the array

            //first two bytes are the kernel version
            buffer[0] = (version & 0xff) as u8;
            buffer[1] = ((version >> 8) & 0xff) as u8;

            // the next two bytes are the header length
            buffer[2] = (padding_header_len & 0xff) as u8;
            buffer[3] = ((padding_header_len >> 8) & 0xff) as u8;
            
            // the next 4 bytes are the total app length including the header
            buffer[4] = (padding_app_length & 0xff) as u8;
            buffer[5] = ((padding_app_length >> 8) & 0xff) as u8;
            buffer[6] = ((padding_app_length >> 16) & 0xff) as u8;
            buffer[7] = ((padding_app_length >> 24) & 0xff) as u8;
            
            // we set the flags to 0
            for i in 8..12 {
                buffer[i] = 0x00 as u8;
            }

            // xor of the previous values
            buffer[12] = (buffer[0] ^ buffer[4] ^ buffer[8]) as u8;
            buffer[13] = (buffer[1] ^ buffer[5] ^ buffer[9]) as u8;
            buffer[14] = (buffer[2] ^ buffer[6] ^ buffer[10]) as u8;
            buffer[15] = (buffer[3] ^ buffer[7] ^ buffer[11]) as u8;

            // set the rest of the values to 0xff
            for i in 16..BUF_LEN{
                buffer[i] = 0xff as u8;
            }
        });
        

        // self.buffer.map(|buffer|{
        //     let buf_data = &padding_array[0..TBF_HEADER_LENGTH];
        //     for (i, c) in buffer[0..TBF_HEADER_LENGTH].iter_mut().ennumerate(){
        //         *c = buf_data[i];
        //     }
        // });

    //    unimplemented!();       // writing to flash

        // set up to write padding app to flash

        // let write_count:usize = 0;
        // let mut flash_offset:usize = 0;
        // let write_buffer:[u8;TBF_HEADER_LENGTH] = [0;TBF_HEADER_LENGTH];

        // write_count = padding_array.len()/BUF_LEN;

        // let offset:u32 = 0;

        // for offset in (0..write_count).step_by(BUF_LEN){

        //copy this section of the appbinary into the shared buffer (or maybe directly into the flash?)
        // flash_offset = current_process_end_addr - self.flash_start.get();   // where to get flash_start from?

        // self.enqueue_command(
        //     true,                                   //let the function know that this is the padding header being written
        //     NonvolatileCommand::UserspaceWrite, 
        //     padding_buffer,
        //     flash_offset,
        //     TBF_HEADER_LENGTH,);
        //write it to flash
        let result = self.buffer.take().map_or(Err(ErrorCode::RESERVE), |buffer|{
            let res = self.enqueue_command(
                true,                                   //let the function know that this is the padding header being written
                NonvolatileCommand::UserspaceWrite, 
                buffer,
                current_process_end_addr,
                BUF_LEN,);
            match res {
                    Ok(()) => Ok(()),
                    Err(e) => Err(e),
                }
        });
        match result{
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
        // }
    }

}

/// This is the callback client for the underlying physical storage driver.
impl<'a, C: 'static + Chip> NonvolatileStorageClient for DynamicProcessLoader<'a, C> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize) {         //we will never use this, but we need to implement this anyway
        unimplemented!();

    }

    fn write_done(&self, buffer: &'static mut [u8], length: usize) {            // change it so the callback is issued to the capsule
        // Switch on which user of this capsule generated this callback.
        debug!("Received callback from NV Storage");

        self.client.map(|client| {
            debug!("issuing callback to client");
            client.app_data_write_done(buffer, length);
            }); 

    }
}

// interface exposed to the app_loader capsule
impl<'a, C: 'static + Chip> DynamicProcessLoading for DynamicProcessLoader<'a, C> {

    fn set_client(&self, client: &'static dyn DynamicProcessLoadingClient){
        self.client.set(client);
    }

    fn setup(&self, app_length: usize) -> Result<(usize, usize), ErrorCode> {

        let mut new_app_data = NewApp{      // struct to hold some information about the new app
            size: 0,
            start_addr: 0,
        };

        let flash_start = self.flash.get().as_ptr() as usize;       //start of the flash region

        new_app_data.start_addr = self.flash.get().as_ptr() as usize;
        new_app_data.size = app_length;
         
        match self.find_next_available_address(&mut new_app_data){
            Ok(()) =>
                {
                    let new_start_addr = new_app_data.start_addr;

                    let offset = new_start_addr - flash_start;

                    let new_process_flash = self
                        .flash
                        .get()
                        .get(offset..offset + app_length)
                        .ok_or(ErrorCode::FAIL)?;
                    let new_process_flash_start = new_process_flash.as_ptr() as usize;

                    self.new_process_flash.set(new_process_flash);
                        
                    self.new_app_start_addr.set(new_app_data.start_addr);
                    self.new_app_length.set(new_app_data.size);
                    
                    // reset the struct values for a new app 
                    new_app_data.size = 0;
                    new_app_data.start_addr = 0;

                    debug!("Found next available address!");

                    Ok((new_process_flash_start, app_length))
                },   
            Err(err) => 
            {
                debug!("Failed to setup for new app.");
                Ok((0,0))
            },
        }
    }

    fn write_app_data(
        &self,
        flag: bool,
        buffer: &'static mut [u8],
        offset: usize,
        length: usize,
        processid: ProcessId,
    ) -> Result<(), ErrorCode> {

        if !flag{
            let res = self.enqueue_command(false, NonvolatileCommand::UserspaceWrite, buffer, offset, length);
            match res{
                Ok(()) => Ok(()),
                Err(e) => Err(e),
            }
        }
        else{   
            unimplemented!();   //when the app is pending (the capsule currently returns something but we don't want it to do anything here)
        }
    }


    fn load(&self) -> Result<(), ErrorCode> {
        let index = self.find_open_process_slot().ok_or(ErrorCode::FAIL)?;
        let process_flash = self.new_process_flash.take().ok_or(ErrorCode::FAIL)?;
        let remaining_memory = self.app_memory.take().ok_or(ErrorCode::FAIL)?;

        debug!("index: {:?}", index);
        // debug!("process_flash size: {:?}", process_flash.as_ptr().len());
        // debug!("remaining_memory: {:?}", remaining_memory);

        // Get the first eight bytes of flash to check if there is another app.
        let test_header_slice = match process_flash.get(0..8) {
            Some(s) => s,
            None => {
                // Not enough flash to test for another app. This just means
                // we are at the end of flash, and there are no more apps to
                // load. => This case is error in loading app by ota_app, because it means that there is no valid tbf header!
                debug!("Failed test_header_slice");
                return Err(ErrorCode::FAIL);
            }
        };

        debug!("test_header_slice: {:?}", test_header_slice);

        // Pass the first eight bytes to tbfheader to parse out the length of
        // the tbf header and app. We then use those values to see if we have
        // enough flash remaining to parse the remainder of the header.
        let (version, header_length, entry_length) = match tock_tbf::parse::parse_tbf_header_lengths(
            test_header_slice.try_into().or(Err(ErrorCode::FAIL))?,
        ) {
            Ok((v, hl, el)) => (v, hl, el),
            Err(tock_tbf::types::InitialTbfParseError::InvalidHeader(_entry_length)) => {
                // If we could not parse the header, then we want to skip over
                // this app and look for the next one. => This case is error in loading app by ota_app
                debug!("check for entry length failed");
                return Err(ErrorCode::FAIL);
            }
            Err(tock_tbf::types::InitialTbfParseError::UnableToParse) => {
                // Since Tock apps use a linked list, it is very possible the
                // header we started to parse is intentionally invalid to signal
                // the end of apps. This is ok and just means we have finished
                // loading apps. => This case is error in loading app by ota_app
                debug!("unable to parse header");
                return Err(ErrorCode::FAIL);
            }
        };

        // Now we can get a slice which only encompasses the length of flash
        // described by this tbf header.  We will either parse this as an actual
        // app, or skip over this region.
        // debug!("header parsed");
        // debug!("header length: {}", header_length);
        // debug!("entry length: {}", entry_length);

        // debug!("process flash: {:?}", process_flash.as_ptr());
        // debug!("process flash size: {}", process_flash.len());

        let entry_flash = process_flash
            .get(0..entry_length as usize)
            .ok_or(ErrorCode::FAIL)?;
        
        // debug!("entry_flash = process_flash");
        // debug!("header length: {}", header_length);

        // Need to reassign remaining_memory in every iteration so the compiler
        // knows it will not be re-borrowed.
        if header_length > 0 {
            // If we found an actual app header, try to create a `Process`
            // object. We also need to shrink the amount of remaining memory
            // based on whatever is assigned to the new process if one is
            // created.

            // Try to create a process object from that app slice. If we don't
            // get a process and we didn't get a loading error (aka we got to
            // this point), then the app is a disabled process or just padding.

            // debug!("creating process");

            let process_option = unsafe {
                let result = ProcessStandard::create(
                    self.kernel,
                    self.chip,
                    entry_flash,
                    header_length as usize,
                    version,
                    remaining_memory,
                    self.fault_policy,
                    true,
                    index,
                );
                match result {
                    Ok((process_option, unused_memory)) => {
                        self.app_memory.set(unused_memory);
                        process_option
                    }
                    Err((_err, unused_memory)) => {
                        self.app_memory.set(unused_memory);
                        return Err(ErrorCode::FAIL);
                    }
                }
            };
            process_option.map(|process| {
                if config::CONFIG.debug_load_processes {
                    let addresses = process.get_addresses();
                        debug!(
                        "Loaded process[{}] from flash={:#010X}-{:#010X} into sram={:#010X}-{:#010X} = {:?}",
                        index,
                        entry_flash.as_ptr() as usize,
                        entry_flash.as_ptr() as usize + entry_flash.len() - 1,
                        addresses.sram_start,
                        addresses.sram_end - 1,
                        process.get_process_name()
                    );
                }
            });

            // //we return sram_end_addresses
            // let addresses = process.get_addresses();
            // sram_end_addresses = addresses.sram_end;

            // //we return process_copy
            // process_copy = Some(process);

            // self.app_memory.set(unused_memory);
            self.procs.map(|procs| procs[index] = process_option);

            let capability = create_capability!(crate::capabilities::ProcessApprovalCapability);
            self.procs.map(|procs| {
                procs[index].map(|p| {
                    p.mark_credentials_pass(
                        None,
                        crate::process::ShortID::LocallyUnique,
                        &capability,
                    );
                    if config::CONFIG.debug_process_credentials {
                        debug!("Running {}", p.get_process_name());
                    }
                });
            });
            self.new_app_start_addr.set(0);    // reset the global new_app_start_address
            self.new_app_length.set(0);

            let new_process_count = self.find_open_process_slot().unwrap_or_default();  // should never default because we have at least the OTA helper app running
            // check if there is a remnant app in that space
            let current_process_end_addr = entry_flash.as_ptr() as usize + entry_flash.len();
            let mut next_process_start_addr:usize = 0;

            self.procs.map(|procs| {
                for (proc_index, value) in procs.iter().enumerate(){
                    if proc_index == new_process_count{
                    {
                        debug!("Loaded App Index: {:?}", index);
                        debug!("New App Index: {:?}", new_process_count);
                        debug!("Current process end address: {:?}",current_process_end_addr);
                        match procs[proc_index]{
                            Some(app)=>{
                                debug!("There is an app here, this should be the length");
                                next_process_start_addr = app.get_addresses().flash_start as usize;
                            }
                            None => {
                                debug!("There are no more apps, setting padding until the end of flash");
                                next_process_start_addr = self.flash_end.get() as usize;
                                debug!("End of flash is: {:?}", next_process_start_addr);
                            }
                        }
                    }
                }
                }
            });
            
            let padding_app_length = next_process_start_addr - current_process_end_addr;
            debug!("padding_app_length: {:?}",padding_app_length);

            let padding_result = self.write_padding_app(current_process_end_addr, padding_app_length, version, header_length as usize);
                match padding_result {
                    Ok(()) => {
                        // if config::CONFIG.debug_load_processes {
                            debug!("Padding app written");
                        // }
                        // Ok(())
                        // Ok((current_process_end_addr, padding_app_length, version, header_length as usize))
                    }
                    Err(_err) => {   
                        // if config::CONFIG.debug_load_processes {
                            debug!("Error writing padding app");
                        // }
                        return Err(ErrorCode::FAIL);
                    }
                }

            // self.procs.map(|procs| {
                // let current_process = procs[index];
                // let next_process = procs[index+1];
                
                // let mut current_process_end_address = 0;
                // let mut next_process_start_address = 0;
                // procs[index].map(|p|{
                //     current_process_end_address = p.unwrap().get_addresses().flash_end as usize+ 1;
                // });
                // procs[index + 1].map(|p|{
                //     next_process_start_address = p.unwrap().get_addresses().flash_start as usize;
                // });
                // let current_addresses = procs[index].get_addresses();

                // let current_process_end_addr = entry_flash.as_ptr() as usize + entry_flash.len();
                // debug!("Current process end address: {:?}",current_process_end_addr);
                

                // if let Some(next_process_start_addr) = procs[index + 1].unwrap().get_addresses().flash_start as usize;
                // debug!("Next process start address: {:?}",next_process_start_addr);
    
                // let padding_app_length = next_process_start_addr - current_process_end_addr;
                // debug!("padding_app_lengths: {:?}",padding_app_length);
    
                // let padding_result = self.write_padding_app(current_process_end_addr, padding_app_length, version, header_length as usize);
                // match padding_result {
                //     Ok(()) => {
                //         if config::CONFIG.debug_load_processes {
                //             debug!("Padding app written");
                //         }
                //         Ok(())
                //         // Ok((current_process_end_addr, padding_app_length, version, header_length as usize))
                //     }
                //     Err(_err) => {   
                //         if config::CONFIG.debug_load_processes {
                //             debug!("Error writing padding app");
                //         }
                //         return Err(ErrorCode::FAIL);
                //     }
                // }
            // });
        } else {
            //header length 0 means invalid header
            return Err(ErrorCode::FAIL);
        }

        // write padding app after the current process

        

        Ok(())
    }
}
