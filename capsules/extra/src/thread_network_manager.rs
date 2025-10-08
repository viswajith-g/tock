use kernel::hil::virtual_network_interface::{TenantId, VirtualNetworkInterface, VirtualTxClient, VirtualRxClient};
use kernel::hil::radio::{RadioConfig, RadioChannel};
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::process::{ProcessId, Error};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::ErrorCode;
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::debug;

use kernel::process::ShortId;

use capsules_core::driver;
pub const DRIVER_NUM: usize = driver::NUM::ThreadNetworkManager as usize;

#[derive(Default)]
pub struct AppState {
    tx_pending: bool,  // Track if Tx is in progress
}

/// Thread Network Manager
pub struct ThreadNetworkManager<V: VirtualNetworkInterface + 'static, R: RadioConfig<'static> + 'static> {
    virtual_interface: &'static V,
    radio: &'static R,
    apps: Grant<AppState, UpcallCount<2>, AllowRoCount<1>, AllowRwCount<1>>,
}

impl<V: VirtualNetworkInterface + 'static, R: RadioConfig<'static> + 'static> ThreadNetworkManager<V, R> {
    pub fn new(
        virtual_interface: &'static V,
        radio: &'static R,
        grant: Grant<AppState, UpcallCount<2>, AllowRoCount<1>, AllowRwCount<1>>,
    ) -> Self {
        Self {
            virtual_interface,
            radio,
            apps: grant,
        }
    }

     fn get_tenant_id(&self, process_id: ProcessId) -> TenantId {
        let short_id = process_id.short_app_id();
        self.compute_tenant_id(short_id)
    }

    /// Compute tenant ID from ShortId
    fn compute_tenant_id(&self, short_id: ShortId) -> TenantId {
        match short_id {
            ShortId::LocallyUnique => {
                // kernel::debug!("Warning: LocallyUnique ShortId - using default ID");
                0xFFFFFFFF
            }
            ShortId::Fixed(id) => {
                id.get()
            }
        }
    }

    /// Convert channel to RadioChannel
    fn channel_to_radiochannel(channel: u8) -> Result<RadioChannel, ErrorCode> {
        match channel {
            11 => Ok(RadioChannel::Channel11),
            12 => Ok(RadioChannel::Channel12),
            13 => Ok(RadioChannel::Channel13),
            14 => Ok(RadioChannel::Channel14),
            15 => Ok(RadioChannel::Channel15),
            16 => Ok(RadioChannel::Channel16),
            17 => Ok(RadioChannel::Channel17),
            18 => Ok(RadioChannel::Channel18),
            19 => Ok(RadioChannel::Channel19),
            20 => Ok(RadioChannel::Channel20),
            21 => Ok(RadioChannel::Channel21),
            22 => Ok(RadioChannel::Channel22),
            23 => Ok(RadioChannel::Channel23),
            24 => Ok(RadioChannel::Channel24),
            25 => Ok(RadioChannel::Channel25),
            26 => Ok(RadioChannel::Channel26),
            _ => Err(ErrorCode::INVAL),
        }
    }
}

impl<V: VirtualNetworkInterface + 'static, R: RadioConfig<'static> + 'static> SyscallDriver 
    for ThreadNetworkManager<V, R> 
{
    fn command(
        &self,
        command_num: usize,
        arg1: usize,
        _arg2: usize,
        process_id: ProcessId,
    ) -> CommandReturn {
        match command_num {
            // Check if driver exists
            0 => CommandReturn::success(),

            // Get app id
            1 => {
                let app_id = self.get_tenant_id(process_id);
                CommandReturn::success_u32(app_id as u32)
            }

            // Send packet
            2 => {

                let len = arg1;
                let app_id = self.get_tenant_id(process_id);

                // kernel::debug!("ThreadNetworkManager: send from TID=0x{:04x} (len={})", 
                //               app_id, len);

                self.apps
                    .enter(process_id, |app, kernel_data| {
                        // Check if already sending
                        if app.tx_pending {
                            kernel::debug!("Tx busy");
                            return Err(ErrorCode::BUSY);
                        }

                        kernel_data
                            .get_readonly_processbuffer(0)
                            .and_then(|tx_buffer| {
                                tx_buffer.enter(|payload| {
                                    if len > payload.len() {
                                        debug!("Payload size exceeds limit");
                                        return Err(ErrorCode::SIZE);
                                    }

                                    // Create a temporary buffer to copy app data
                                    // We need to copy because process buffers can't be held across yields
                                    let mut temp_buf = [0u8; 126];
                                    let copy_len = core::cmp::min(len, temp_buf.len());
                                    
                                    for i in 0..copy_len {
                                        temp_buf[i] = payload[i].get();
                                    }

                                    match self.virtual_interface.send(app_id, &temp_buf, copy_len) {
                                        Ok(()) => {
                                            debug!("Transmission scheduled");
                                            app.tx_pending = true;
                                            Ok(())
                                        }
                                        Err(e) => {
                                            debug!("Transmission schedule failed: {:?}", e);
                                            Err(e)
                                        }
                                    }
                                })
                            })
                            .unwrap_or_else(|e| {
                                kernel::debug!("Failed to get Tx buffer: {:?}", e);
                                Err(ErrorCode::INVAL)
                            })
                    })
                    .map_or_else(
                        |e| {
                            kernel::debug!("Grant entry failure: {:?}", e);
                            CommandReturn::failure(e.into())
                        },
                        |res| match res {
                            Ok(()) => CommandReturn::success(),
                            Err(e) => CommandReturn::failure(e),
                        },
                    )
            }

            // Set PAN ID
            3 => {
                let pan_id = arg1 as u16;
                self.radio.set_pan(pan_id);
                CommandReturn::success()
            }

            // Set channel (11-26)
            4 => {
                let channel = arg1 as u8;
                match Self::channel_to_radiochannel(channel) {
                    Ok(radio_channel) => {
                        self.radio.set_channel(radio_channel);
                        CommandReturn::success()
                    }
                    Err(e) => CommandReturn::failure(e),
                }
            }

            // Get current channel
            5 => {
                CommandReturn::success_u32(self.radio.get_channel() as u32)
            }

            // Get PAN ID
            6 => {
                CommandReturn::success_u32(self.radio.get_pan() as u32)
            }

            // Set Tx power
            7 => {
                let power_dbm = arg1 as i8;
                match self.radio.set_tx_power(power_dbm) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            // Get Tx power
            8 => {
                CommandReturn::success_u32(self.radio.get_tx_power() as u32)
            }

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), Error> {
        self.apps.enter(process_id, |_, _| {})
    }
}

impl<V: VirtualNetworkInterface + 'static, R: RadioConfig<'static> + 'static> VirtualRxClient 
    for ThreadNetworkManager<V, R> 
{
    fn receive(&self, app_id: TenantId, packet: &[u8], len: usize) {
        // kernel::debug!("ThreadNetworkManager::receive: app_id=0x{:04x}, len={}", app_id, len);
        
        self.apps.each(|process_id, _app, kernel_data| {
            let process_tenant_id = self.get_tenant_id(process_id);
            
            if process_tenant_id == app_id {
                kernel::debug!("Notifying process {:?}", process_id);
                
                let _ = kernel_data
                    .get_readwrite_processbuffer(0)
                    .and_then(|rx_buffer| {
                        rx_buffer.mut_enter(|dest| {
                            let copy_len = core::cmp::min(len, dest.len());
                            for i in 0..copy_len {
                                dest[i].set(packet[i]);
                            }
                            copy_len
                        })
                    })
                    .map(|copied_len| {
                        let _ = kernel_data.schedule_upcall(0, (app_id as usize, copied_len, 0));
                    });
            }
        });
    }
}

impl<V: VirtualNetworkInterface + 'static, R: RadioConfig<'static> + 'static> VirtualTxClient 
    for ThreadNetworkManager<V, R> 
{
    fn send_done(&self, app_id: TenantId, result: Result<(), ErrorCode>) {
        // kernel::debug!("ThreadNetworkManager::send_done: app_id=0x{:04x}, result={:?}", 
                    //   app_id, result);
        
        self.apps.each(|process_id, app, kernel_data| {
            let process_tenant_id = self.get_tenant_id(process_id);
            
            if process_tenant_id == app_id && app.tx_pending {
                app.tx_pending = false;
                
                kernel::debug!("Notifying process {:?}", process_id);
                
                let result_code = match result {
                    Ok(()) => 0,
                    Err(e) => e as usize,
                };
                let _ = kernel_data.schedule_upcall(1, (result_code, 0, 0));
            }
        });
    }
}