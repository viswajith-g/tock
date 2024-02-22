//! Helper functions related to Tock processes by OTA_app.

use core::cell::Cell;
use core::cmp;

use crate::capabilities::MemoryAllocationCapability;
use crate::config;
use crate::create_capability;
use crate::debug;
use crate::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use crate::kernel::Kernel;
use crate::platform::chip::Chip;
use crate::process::{self, Process};
use crate::process_loading::ProcessLoadError;
use crate::process_policies::ProcessFaultPolicy;
use crate::process_standard::ProcessStandard;
use crate::syscall_driver::{CommandReturn, SyscallDriver};
use crate::utilities::cells::{MapCell, OptionalCell};
use crate::ErrorCode;

struct NewApp{
    // App size requested by ota app
    size: usize,
    // dynamic_flash_start_addr points the start address that a new app will be loaded
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

    /// Instruct the kernel to load and execute the process.
    ///
    /// This tells the kernel to try to actually execute the new process that
    /// was just installed in flash from the preceding `setup()` call.
    fn load(&self) -> Result<(), ErrorCode>;
}

pub struct DynamicProcessLoader<C: 'static + Chip> {
    kernel: &'static Kernel,
    chip: &'static C,
    fault_policy: &'static dyn ProcessFaultPolicy,

    procs: MapCell<&'static mut [Option<&'static dyn process::Process>]>,
    flash: Cell<&'static [u8]>,
    app_memory: OptionalCell<&'static mut [u8]>,
    flash_start: Cell<usize>,
    flash_end: Cell<usize>,
    new_process_flash: OptionalCell<&'static [u8]>,
}

impl<C: 'static + Chip> DynamicProcessLoader<C> {
    pub fn new(
        processes: &'static mut [Option<&'static dyn process::Process>],
        kernel: &'static Kernel,
        chip: &'static C,
        flash: &'static [u8],
        fault_policy: &'static dyn ProcessFaultPolicy,
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

    fn check_for_padding_app(&self, new_app: &mut NewApp) -> Result<bool, ProcessLoadError> {
        //We only need the tbf header information to get the size of a loaded app
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

        //If a padding app exists at the start address satisfying MPU rules, we load the new app
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
        //We only need tbf header information to get the size of a loaded app
        let header_info = unsafe { core::slice::from_raw_parts(new_app.start_addr as *const u8, 8) };

        let test_header_slice = match header_info.get(0..8) {
            Some(s) => s,
            None => {
                // Not enough flash to test for another app. This just means
                // We are at the end of flash (0x80000).
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
}


impl<C: 'static + Chip> DynamicProcessLoading for DynamicProcessLoader<C> {
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
                    
                    // reset the struct values for a new app 
                    new_app_data.size = 0;
                    new_app_data.start_addr = 0;    

                    Ok((new_process_flash_start, app_length))
                },   
            Err(err) => 
            {
                debug!("Failed to setup for new app.");
                Ok((0,0))
            },
        }
    }

    fn load(&self) -> Result<(), ErrorCode> {

        //TODO: Add padding between the new app and other existing apps. 


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
        debug!("header parsed");
        debug!("header length: {}", header_length);
        debug!("entry length: {}", entry_length);

        debug!("process flash: {:?}", process_flash.as_ptr());
        debug!("process flash size: {}", process_flash.len());

        let entry_flash = process_flash
            .get(0..entry_length as usize)
            .ok_or(ErrorCode::FAIL)?;
        
        debug!("entry_flash=process_flash");
        debug!("header length: {}", header_length);

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

            debug!("creating process");

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
        } else {
            //header length 0 means invalid header
            return Err(ErrorCode::FAIL);
        }

        Ok(())
    }
}
