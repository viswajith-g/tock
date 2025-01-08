// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Virtualize a SPI master bus to enable multiple users of the SPI bus.

use core::cell::Cell;
use kernel::collections::list::{List, ListLink, ListNode};
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil;
use kernel::hil::spi::SpiMasterClient;
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::ErrorCode;

/// The Mux struct manages multiple Spi clients. Each client may have
/// at most one outstanding Spi request.
pub struct MuxSpiMaster<'a, Spi: hil::spi::SpiMaster<'a>> {
    spi: &'a Spi,
    devices: List<'a, VirtualSpiMasterDevice<'a, Spi>>,
    inflight: OptionalCell<&'a VirtualSpiMasterDevice<'a, Spi>>,
    deferred_call: DeferredCall,
}

impl<'a, Spi: hil::spi::SpiMaster<'a>> hil::spi::SpiMasterClient for MuxSpiMaster<'a, Spi> {
    fn read_write_done(
        &self,
        write_buffer: SubSliceMut<'static, u8>,
        read_buffer: Option<SubSliceMut<'static, u8>>,
        status: Result<usize, ErrorCode>,
    ) {
        let dev = self.inflight.take();
        // Need to do next op before signaling so we get some kind of
        // sharing. Otherwise a call to read_write in the callback
        // can allow this client to never relinquish the device.
        // -pal 7/30/21
        self.do_next_op();
        dev.map(move |device| {
            device.read_write_done(write_buffer, read_buffer, status);
        });
    }
}

impl<'a, Spi: hil::spi::SpiMaster<'a>> MuxSpiMaster<'a, Spi> {
    pub fn new(spi: &'a Spi) -> Self {
        Self {
            spi,
            devices: List::new(),
            inflight: OptionalCell::empty(),
            deferred_call: DeferredCall::new(),
        }
    }

    fn do_next_op(&self) {
        if self.inflight.is_none() {
            let mnode = self
                .devices
                .iter()
                .find(|node| node.operation.get() != Op::Idle);
            mnode.map(|node| {
                let configuration = node.configuration.get();
                let cs = configuration.chip_select;
                let _ = self.spi.specify_chip_select(cs);

                let op = node.operation.get();
                // Need to set idle here in case callback changes state
                node.operation.set(Op::Idle);
                match op {
                    Op::ReadWriteBytes => {
                        // Only async operations want to block by setting
                        // the devices as inflight.
                        self.inflight.set(node);
                        node.txbuffer.take().map(|txbuffer| {
                            let rresult = self.spi.set_rate(configuration.rate);
                            let polresult = self.spi.set_polarity(configuration.polarity);
                            let phaseresult = self.spi.set_phase(configuration.phase);
                            if rresult.is_err() || polresult.is_err() || phaseresult.is_err() {
                                node.txbuffer.replace(txbuffer);
                                node.operation.set(Op::ReadWriteDone(Err(ErrorCode::INVAL)));
                                self.do_next_op_async();
                            } else {
                                let rxbuffer = node.rxbuffer.take();
                                if let Err((e, write_buffer, read_buffer)) =
                                    self.spi.read_write_bytes(txbuffer, rxbuffer)
                                {
                                    node.txbuffer.replace(write_buffer);
                                    read_buffer.map(|buffer| {
                                        node.rxbuffer.replace(buffer);
                                    });
                                    node.operation.set(Op::ReadWriteDone(Err(e)));
                                    self.do_next_op_async();
                                }
                            }
                        });
                    }
                    Op::ReadWriteDone(status) => {
                        node.txbuffer.take().map(|write_buffer| {
                            let read_buffer = node.rxbuffer.take();
                            self.read_write_done(write_buffer, read_buffer, status);
                        });
                    }
                    Op::Idle => {} // Can't get here...
                }
            });
        } else {
            self.inflight.map(|node| {
                match node.operation.get() {
                    // we have to report an error
                    Op::ReadWriteDone(status) => {
                        node.txbuffer.take().map(|write_buffer| {
                            let read_buffer = node.rxbuffer.take();
                            self.read_write_done(write_buffer, read_buffer, status);
                        });
                    }
                    _ => {} // Something is really in flight
                }
            });
        }
    }

    /// Asynchronously executes the next operation, if any. Used by calls
    /// to trigger do_next_op such that it will execute after the call
    /// returns. This is important in case the operation triggers an error,
    /// requiring a callback with an error condition; if the operation
    /// is executed synchronously, the callback may be reentrant (executed
    /// during the downcall). Please see
    /// <https://github.com/tock/tock/issues/1496>
    fn do_next_op_async(&self) {
        self.deferred_call.set();
    }
}

impl<'a, Spi: hil::spi::SpiMaster<'a>> DeferredCallClient for MuxSpiMaster<'a, Spi> {
    fn handle_deferred_call(&self) {
        self.do_next_op();
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

#[derive(Copy, Clone, PartialEq)]
enum Op {
    Idle,
    ReadWriteBytes,
    ReadWriteDone(Result<usize, ErrorCode>),
}

// Structure used to store the SPI configuration of a client/virtual device,
// so it can restored on each operation.
struct SpiConfiguration<'a, Spi: hil::spi::SpiMaster<'a>> {
    chip_select: Spi::ChipSelect,
    polarity: hil::spi::ClockPolarity,
    phase: hil::spi::ClockPhase,
    rate: u32,
}

// Have to do this manually because otherwise the Copy and Clone are parameterized
// by Spi::ChipSelect and don't work for Cells.
// https://stackoverflow.com/questions/63132174/how-do-i-fix-the-method-clone-exists-but-the-following-trait-bounds-were-not
impl<'a, Spi: hil::spi::SpiMaster<'a>> Copy for SpiConfiguration<'a, Spi> {}
impl<'a, Spi: hil::spi::SpiMaster<'a>> Clone for SpiConfiguration<'a, Spi> {
    fn clone(&self) -> SpiConfiguration<'a, Spi> {
        *self
    }
}

pub struct VirtualSpiMasterDevice<'a, Spi: hil::spi::SpiMaster<'a>> {
    mux: &'a MuxSpiMaster<'a, Spi>,
    configuration: Cell<SpiConfiguration<'a, Spi>>,
    txbuffer: MapCell<SubSliceMut<'static, u8>>,
    rxbuffer: MapCell<SubSliceMut<'static, u8>>,
    operation: Cell<Op>,
    next: ListLink<'a, VirtualSpiMasterDevice<'a, Spi>>,
    client: OptionalCell<&'a dyn hil::spi::SpiMasterClient>,
}

impl<'a, Spi: hil::spi::SpiMaster<'a>> VirtualSpiMasterDevice<'a, Spi> {
    pub fn new(
        mux: &'a MuxSpiMaster<'a, Spi>,
        chip_select: Spi::ChipSelect,
    ) -> VirtualSpiMasterDevice<'a, Spi> {
        VirtualSpiMasterDevice {
            mux,
            configuration: Cell::new(SpiConfiguration {
                chip_select,
                polarity: hil::spi::ClockPolarity::IdleLow,
                phase: hil::spi::ClockPhase::SampleLeading,
                rate: 100_000,
            }),
            txbuffer: MapCell::empty(),
            rxbuffer: MapCell::empty(),
            operation: Cell::new(Op::Idle),
            next: ListLink::empty(),
            client: OptionalCell::empty(),
        }
    }

    /// Must be called right after `static_init!()`.
    pub fn setup(&'a self) {
        self.mux.devices.push_head(self);
    }
}

impl<'a, Spi: hil::spi::SpiMaster<'a>> hil::spi::SpiMasterClient
    for VirtualSpiMasterDevice<'a, Spi>
{
    fn read_write_done(
        &self,
        write_buffer: SubSliceMut<'static, u8>,
        read_buffer: Option<SubSliceMut<'static, u8>>,
        status: Result<usize, ErrorCode>,
    ) {
        self.client.map(move |client| {
            client.read_write_done(write_buffer, read_buffer, status);
        });
    }
}

impl<'a, Spi: hil::spi::SpiMaster<'a>> ListNode<'a, VirtualSpiMasterDevice<'a, Spi>>
    for VirtualSpiMasterDevice<'a, Spi>
{
    fn next(&'a self) -> &'a ListLink<'a, VirtualSpiMasterDevice<'a, Spi>> {
        &self.next
    }
}

impl<'a, Spi: hil::spi::SpiMaster<'a>> hil::spi::SpiMasterDevice<'a>
    for VirtualSpiMasterDevice<'a, Spi>
{
    fn set_client(&self, client: &'a dyn SpiMasterClient) {
        self.client.set(client);
    }

    fn configure(
        &self,
        cpol: hil::spi::ClockPolarity,
        cpal: hil::spi::ClockPhase,
        rate: u32,
    ) -> Result<(), ErrorCode> {
        if self.operation.get() == Op::Idle {
            let mut configuration = self.configuration.get();
            configuration.polarity = cpol;
            configuration.phase = cpal;
            configuration.rate = rate;
            self.configuration.set(configuration);
            Ok(())
        } else {
            Err(ErrorCode::BUSY)
        }
    }

    fn read_write_bytes(
        &self,
        write_buffer: SubSliceMut<'static, u8>,
        mut read_buffer: Option<SubSliceMut<'static, u8>>,
    ) -> Result<
        (),
        (
            ErrorCode,
            SubSliceMut<'static, u8>,
            Option<SubSliceMut<'static, u8>>,
        ),
    > {
        if self.operation.get() == Op::Idle {
            self.txbuffer.replace(write_buffer);
            if let Some(rb) = read_buffer.take() {
                self.rxbuffer.put(rb);
            }
            self.operation.set(Op::ReadWriteBytes);
            self.mux.do_next_op();
            Ok(())
        } else {
            Err((ErrorCode::BUSY, write_buffer, read_buffer))
        }
    }

    fn set_polarity(&self, cpol: hil::spi::ClockPolarity) -> Result<(), ErrorCode> {
        if self.operation.get() == Op::Idle {
            let mut configuration = self.configuration.get();
            configuration.polarity = cpol;
            self.configuration.set(configuration);
            Ok(())
        } else {
            Err(ErrorCode::BUSY)
        }
    }

    fn set_phase(&self, cpal: hil::spi::ClockPhase) -> Result<(), ErrorCode> {
        if self.operation.get() == Op::Idle {
            let mut configuration = self.configuration.get();
            configuration.phase = cpal;
            self.configuration.set(configuration);
            Ok(())
        } else {
            Err(ErrorCode::BUSY)
        }
    }

    fn set_rate(&self, rate: u32) -> Result<(), ErrorCode> {
        if self.operation.get() == Op::Idle {
            let mut configuration = self.configuration.get();
            configuration.rate = rate;
            self.configuration.set(configuration);
            Ok(())
        } else {
            Err(ErrorCode::BUSY)
        }
    }

    fn get_polarity(&self) -> hil::spi::ClockPolarity {
        self.configuration.get().polarity
    }

    fn get_phase(&self) -> hil::spi::ClockPhase {
        self.configuration.get().phase
    }

    fn get_rate(&self) -> u32 {
        self.configuration.get().rate
    }
}

pub struct SpiSlaveDevice<'a, Spi: hil::spi::SpiSlave<'a>> {
    spi: &'a Spi,
    client: OptionalCell<&'a dyn hil::spi::SpiSlaveClient>,
}

impl<'a, Spi: hil::spi::SpiSlave<'a>> SpiSlaveDevice<'a, Spi> {
    pub const fn new(spi: &'a Spi) -> SpiSlaveDevice<'a, Spi> {
        SpiSlaveDevice {
            spi,
            client: OptionalCell::empty(),
        }
    }
}

impl<'a, Spi: hil::spi::SpiSlave<'a>> hil::spi::SpiSlaveClient for SpiSlaveDevice<'a, Spi> {
    fn read_write_done(
        &self,
        write_buffer: Option<&'static mut [u8]>,
        read_buffer: Option<&'static mut [u8]>,
        len: usize,
        status: Result<(), ErrorCode>,
    ) {
        self.client.map(move |client| {
            client.read_write_done(write_buffer, read_buffer, len, status);
        });
    }

    fn chip_selected(&self) {
        self.client.map(move |client| {
            client.chip_selected();
        });
    }
}

impl<'a, Spi: hil::spi::SpiSlave<'a>> hil::spi::SpiSlaveDevice<'a> for SpiSlaveDevice<'a, Spi> {
    fn set_client(&self, client: &'a dyn hil::spi::SpiSlaveClient) {
        self.client.set(client);
    }

    fn configure(
        &self,
        cpol: hil::spi::ClockPolarity,
        cpal: hil::spi::ClockPhase,
    ) -> Result<(), ErrorCode> {
        self.spi.set_polarity(cpol)?;
        self.spi.set_phase(cpal)
    }

    fn read_write_bytes(
        &self,
        write_buffer: Option<&'static mut [u8]>,
        read_buffer: Option<&'static mut [u8]>,
        len: usize,
    ) -> Result<
        (),
        (
            ErrorCode,
            Option<&'static mut [u8]>,
            Option<&'static mut [u8]>,
        ),
    > {
        self.spi.read_write_bytes(write_buffer, read_buffer, len)
    }

    fn set_polarity(&self, cpol: hil::spi::ClockPolarity) -> Result<(), ErrorCode> {
        self.spi.set_polarity(cpol)
    }

    fn set_phase(&self, cpal: hil::spi::ClockPhase) -> Result<(), ErrorCode> {
        self.spi.set_phase(cpal)
    }

    fn get_polarity(&self) -> hil::spi::ClockPolarity {
        self.spi.get_polarity()
    }

    fn get_phase(&self) -> hil::spi::ClockPhase {
        self.spi.get_phase()
    }
}
