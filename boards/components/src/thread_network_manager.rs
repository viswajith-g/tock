use core::mem::MaybeUninit;

use kernel::capabilities;
use kernel::create_capability;
use kernel::component::Component;
use kernel::hil::radio::{RadioConfig, RadioData};
use capsules_extra::thread_network_manager::ThreadNetworkManager;
use kernel::hil::virtual_network_interface::VirtualNetworkInterface;
use capsules_extra::virtualizers::network::virtual_thread::VirtualThreadInterface;

#[macro_export]
macro_rules! thread_network_manager_component_static {
    ($R:ty $(,)?) => {{
        let virtual_thread = kernel::static_buf!(
            capsules_extra::virtualizers::network::virtual_thread::VirtualThreadInterface<
                'static,
                $R,
            >
        );
        let network_manager = kernel::static_buf!(
            capsules_extra::thread_network_manager::ThreadNetworkManager<
                capsules_extra::virtualizers::network::virtual_thread::VirtualThreadInterface<
                    'static,
                    $R,
                >,
                $R,
            >
        );
        
        let thread_tx_buf = kernel::static_buf!([u8; 125]);
        let thread_rx_buf = kernel::static_buf!([u8; 127]);
        let kernel_tx_buf = kernel::static_buf!([u8; 125]);
        let radio_rx_buf = kernel::static_buf!([u8; 127]);

        (
            virtual_thread,
            network_manager,
            thread_tx_buf,
            thread_rx_buf,
            radio_rx_buf,
        )
    }};
}

pub type ThreadNetworkManagerType<R> = capsules_extra::thread_network_manager::ThreadNetworkManager<
    capsules_extra::virtualizers::network::virtual_thread::VirtualThreadInterface<'static, R>,
    R,
>;

pub struct ThreadNetworkManagerComponent<R: RadioData<'static> + RadioConfig<'static> + 'static> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    radio: &'static R,
}

impl<R: RadioData<'static> + RadioConfig<'static> + 'static> ThreadNetworkManagerComponent<R> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        radio: &'static R,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            radio,
        }
    }
}

impl<R: RadioData<'static> + RadioConfig<'static> + 'static> Component for ThreadNetworkManagerComponent<R> {
    type StaticInput = (
        &'static mut MaybeUninit<VirtualThreadInterface<'static, R>>,
        &'static mut MaybeUninit<ThreadNetworkManager<VirtualThreadInterface<'static, R>, R>>,
        &'static mut MaybeUninit<[u8; 125]>,
        &'static mut MaybeUninit<[u8; 127]>,
        &'static mut MaybeUninit<[u8; 127]>,
    );
    
    type Output = &'static ThreadNetworkManager<VirtualThreadInterface<'static, R>, R>;

    fn finalize(self, static_input: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        let thread_tx_buf = static_input.2.write([0; 125]);
        let thread_rx_buf = static_input.3.write([0; 127]);
        let radio_rx_buf = static_input.4.write([0; 127]);

        // Create virtual thread interface
        let virtual_thread = static_input.0.write(VirtualThreadInterface::new(
            self.radio,
            thread_tx_buf,
            thread_rx_buf,
        ));

        // Set up radio callbacks
        RadioData::set_transmit_client(self.radio, virtual_thread);
        RadioData::set_receive_client(self.radio, virtual_thread);
        RadioData::set_receive_buffer(self.radio, radio_rx_buf);

        // Create network manager
        let network_manager = static_input.1.write(ThreadNetworkManager::new(
            virtual_thread,
            self.radio,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
        ));

        virtual_thread.set_receive_client(network_manager);
        virtual_thread.set_tx_client(network_manager);

        network_manager
    }
}