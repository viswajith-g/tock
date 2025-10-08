use kernel::hil::virtual_network_interface::{TenantId, VirtualNetworkInterface, VirtualRxClient, VirtualTxClient};
use kernel::hil::radio::{RadioConfig, RadioData};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;
use kernel::debug;

const APP_ID_SIZE: usize = 4;

/// Virtual Thread interface - Network virtualization for 802.15.4
pub struct VirtualThreadInterface<'a, R: RadioData<'a> + RadioConfig<'a>> {
    radio: &'a R,
    receive_client: OptionalCell<&'static dyn VirtualRxClient>,
    tx_client: OptionalCell<&'static dyn VirtualTxClient>,
    current_tenant: OptionalCell<TenantId>,
    tx_buffer: TakeCell<'static, [u8]>,
    #[allow(dead_code)]
    rx_buffer: TakeCell<'static, [u8]>,
}

impl<'a, R: RadioData<'a> + RadioConfig<'a>> VirtualThreadInterface<'a, R> {
    pub fn new(
        radio: &'a R,
        tx_buffer: &'static mut [u8],
        rx_buffer: &'static mut [u8],
    ) -> Self {
        Self {
            radio,
            receive_client: OptionalCell::empty(),
            tx_client: OptionalCell::empty(),
            current_tenant: OptionalCell::empty(),
            tx_buffer: TakeCell::new(tx_buffer),
            rx_buffer: TakeCell::new(rx_buffer),
        }
    }

    /// Tag packet with tenant ID (prepend 2 bytes)
        fn tag_packet(&self, app_id: TenantId, payload: &[u8], output: &mut [u8]) -> usize {
        // Write 4-byte tenant ID in big-endian
        let tenant_bytes = app_id.to_be_bytes();
        output[0] = tenant_bytes[0];
        output[1] = tenant_bytes[1];
        output[2] = tenant_bytes[2];
        output[3] = tenant_bytes[3];
        
        let payload_len = core::cmp::min(payload.len(), output.len() - APP_ID_SIZE);
        output[APP_ID_SIZE..APP_ID_SIZE + payload_len]
            .copy_from_slice(&payload[..payload_len]);
        
        APP_ID_SIZE + payload_len
    }

    /// Extract tenant ID from packet (4 bytes)
    fn extract_tenant_id(&self, packet: &[u8]) -> Option<(TenantId, usize)> {
        if packet.len() < APP_ID_SIZE {
            return None;
        }
        
        // Read 4-byte tenant ID in big-endian
        let app_id = u32::from_be_bytes([
            packet[0],
            packet[1],
            packet[2],
            packet[3],
        ]);
        
        // Return app_id and offset to payload start
        Some((app_id, APP_ID_SIZE))
    }
}

impl<'a, R: RadioData<'a> + RadioConfig<'a>> VirtualNetworkInterface for VirtualThreadInterface<'a, R> {
    fn set_receive_client(&self, client: &'static dyn VirtualRxClient) {
        self.receive_client.set(client);
    }

    fn set_tx_client(&self, client: &'static dyn VirtualTxClient) {
        self.tx_client.set(client);
    }

    fn send(&self, app_id: TenantId, packet: &[u8], len: usize) -> Result<(), ErrorCode> {
        self.tx_buffer
            .take()
            .map_or(Err(ErrorCode::BUSY), |buffer| {
                self.current_tenant.set(app_id);
                
                let total_len = self.tag_packet(app_id, &packet[..len], buffer);
                
                match self.radio.transmit(buffer, total_len) {
                    Ok(()) => Ok(()),
                    Err((ecode, buf)) => {
                        self.tx_buffer.replace(buf);
                        self.current_tenant.clear();
                        Err(ecode)
                    }
                }
            })
    }

    fn is_ready(&self) -> bool {
        self.tx_buffer.is_some()
    }
}

impl<'a, R: RadioData<'a> + RadioConfig<'a>> kernel::hil::radio::TxClient for VirtualThreadInterface<'a, R> {
    fn send_done(&self, buffer: &'static mut [u8], _acked: bool, result: Result<(), ErrorCode>) {
        self.tx_buffer.replace(buffer);
        
        // Notify the TX client (NetworkManager) which tenant completed
        self.current_tenant.take().map(|app_id| {
            self.tx_client.map(|client| {
                client.send_done(app_id, result);
            });
        });
    }
}

impl<'a, R: RadioData<'a> + RadioConfig<'a>> kernel::hil::radio::RxClient for VirtualThreadInterface<'a, R> {
    fn receive(
        &self,
        buffer: &'static mut [u8],
        len: usize,
        _lqi: u8,
        _crc_valid: bool,
        result: Result<(), ErrorCode>,
    ) {
        if result.is_err() {
            let _ = self.radio.set_receive_buffer(buffer);
            return;
        }

        // Extract tenant ID from packet
        if let Some((app_id, payload_offset)) = self.extract_tenant_id(&buffer[..len]) {
            
            // Get payload slice
            let payload = &buffer[payload_offset..len];
            let payload_len = len - payload_offset;
            
            // Deliver to client
            self.receive_client.map(|client| {
                client.receive(app_id, payload, payload_len);
            });
        } else {
            kernel::debug!("Failed to rsolve app_id (packet too short)");
        }

        // Return buffer to radio
        let _ = self.radio.set_receive_buffer(buffer);
    }
}