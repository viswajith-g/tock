// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Component to test in kernel udp

// Author: Hudson Ayers <hayers@stanford.edu>

#![allow(dead_code)] // Components are intended to be conditionally included

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_extra::net::ipv6::ipv6_send::IP6SendStruct;
use capsules_extra::net::network_capabilities::{NetworkCapability, UdpVisibilityCapability};
use capsules_extra::net::udp::udp_port_table::UdpPortManager;
use capsules_extra::net::udp::udp_recv::{MuxUdpReceiver, UDPReceiver};
use capsules_extra::net::udp::udp_send::{MuxUdpSender, UDPSendStruct, UDPSender};
use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::hil::time::Alarm;
use kernel::utilities::cells::TakeCell;

#[macro_export]
/// Macro for constructing a mock UDP capsule for tests.
macro_rules! mock_udp_component_static {
    () => {{
        use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
        use capsules_extra::net::udp::udp_recv::UDPReceiver;
        use capsules_extra::net::udp::udp_send::UDPSendStruct;
        let udp_send = kernel::static_buf!(
            UDPSendStruct<
                'static,
                capsules_extra::net::ipv6::ipv6_send::IP6SendStruct<
                    'static,
                    VirtualMuxAlarm<'static, sam4l::ast::Ast<'static>>,
                >,
            >
        );

        let udp_recv = kernel::static_buf!(UDPReceiver<'static>);
        let udp_alarm = kernel::static_buf!(VirtualMuxAlarm<'static, sam4l::ast::Ast>,);

        let mock_udp = kernel::static_buf!(
            capsules_extra::test::udp::MockUdp<'static, VirtualMuxAlarm<'static, sam4l::ast::Ast>>,
        );
        (udp_send, udp_recv, udp_alarm, mock_udp)
    }};
}

pub struct MockUDPComponent {
    udp_send_mux: &'static MuxUdpSender<
        'static,
        IP6SendStruct<'static, VirtualMuxAlarm<'static, sam4l::ast::Ast<'static>>>,
    >,
    udp_recv_mux: &'static MuxUdpReceiver<'static>,
    bound_port_table: &'static UdpPortManager,
    alarm_mux: &'static MuxAlarm<'static, sam4l::ast::Ast<'static>>,
    udp_payload: TakeCell<'static, [u8]>,
    id: u16,
    dst_port: u16,
    net_cap: &'static NetworkCapability,
    udp_vis: &'static UdpVisibilityCapability,
}

impl MockUDPComponent {
    pub fn new(
        udp_send_mux: &'static MuxUdpSender<
            'static,
            IP6SendStruct<'static, VirtualMuxAlarm<'static, sam4l::ast::Ast<'static>>>,
        >,
        udp_recv_mux: &'static MuxUdpReceiver<'static>,
        bound_port_table: &'static UdpPortManager,
        alarm: &'static MuxAlarm<'static, sam4l::ast::Ast<'static>>,
        udp_payload: &'static mut [u8],
        id: u16,
        dst_port: u16,
        net_cap: &'static NetworkCapability,
        udp_vis: &'static UdpVisibilityCapability,
    ) -> MockUDPComponent {
        MockUDPComponent {
            udp_send_mux,
            udp_recv_mux,
            bound_port_table,
            alarm_mux: alarm,
            udp_payload: TakeCell::new(udp_payload),
            id,
            dst_port,
            net_cap,
            udp_vis,
        }
    }
}

impl Component for MockUDPComponent {
    type StaticInput = (
        &'static mut MaybeUninit<
            UDPSendStruct<
                'static,
                capsules_extra::net::ipv6::ipv6_send::IP6SendStruct<
                    'static,
                    VirtualMuxAlarm<'static, sam4l::ast::Ast<'static>>,
                >,
            >,
        >,
        &'static mut MaybeUninit<UDPReceiver<'static>>,
        &'static mut MaybeUninit<VirtualMuxAlarm<'static, sam4l::ast::Ast<'static>>>,
        &'static mut MaybeUninit<
            capsules_extra::test::udp::MockUdp<
                'static,
                VirtualMuxAlarm<'static, sam4l::ast::Ast<'static>>,
            >,
        >,
    );
    type Output = &'static capsules_extra::test::udp::MockUdp<
        'static,
        VirtualMuxAlarm<'static, sam4l::ast::Ast<'static>>,
    >;

    fn finalize(self, s: Self::StaticInput) -> Self::Output {
        let udp_send =
            s.0.write(UDPSendStruct::new(self.udp_send_mux, self.udp_vis));

        let udp_recv = s.1.write(UDPReceiver::new());
        self.udp_recv_mux.add_client(udp_recv);

        let udp_alarm = s.2.write(VirtualMuxAlarm::new(self.alarm_mux));
        udp_alarm.setup();

        let mock_udp = s.3.write(capsules_extra::test::udp::MockUdp::new(
            self.id,
            udp_alarm,
            udp_send,
            udp_recv,
            self.bound_port_table,
            kernel::utilities::leasable_buffer::SubSliceMut::new(
                self.udp_payload.take().expect("missing payload"),
            ),
            self.dst_port,
            self.net_cap,
        ));
        udp_send.set_client(mock_udp);
        udp_recv.set_client(mock_udp);
        udp_alarm.set_alarm_client(mock_udp);
        mock_udp
    }
}
