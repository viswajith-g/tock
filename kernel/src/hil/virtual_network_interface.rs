use crate::ErrorCode;

/// Tenant ID type (4 bytes for shortID)
pub type TenantId = u32;

/// Client for receiving packets with tenant information
pub trait VirtualRxClient {
    /// Called when a packet is received for a specific tenant
    fn receive(&self, app_id: TenantId, packet: &[u8], len: usize);
}

/// Client for TX completion notifications
pub trait VirtualTxClient {
    /// Called when a packet transmission completes
    fn send_done(&self, app_id: TenantId, result: Result<(), ErrorCode>);
}

/// Virtual network interface trait (radio agnostic)
pub trait VirtualNetworkInterface {
    /// Set the client for receiving packets
    fn set_receive_client(&self, client: &'static dyn VirtualRxClient);
    
    /// Set the client for TX completion notifications
    fn set_tx_client(&self, client: &'static dyn VirtualTxClient);

    /// Send a packet with tenant ID
    fn send(&self, app_id: TenantId, packet: &[u8], len: usize) -> Result<(), ErrorCode>;

    /// Check if interface is ready to send
    fn is_ready(&self) -> bool;
}