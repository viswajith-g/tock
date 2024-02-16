// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Generic interface for nonvolatile memory.

use crate::errorcode::ErrorCode; 

/// Simple interface for reading and writing nonvolatile memory. It is expected
/// that drivers for nonvolatile memory would implement this trait.
pub trait NonvolatileStorage<'a> {
    fn set_client(&self, client: &'a dyn NonvolatileStorageClient);

    /// Read `length` bytes starting at address `address` in to the provided
    /// buffer. The buffer must be at least `length` bytes long. The address
    /// must be in the address space of the physical storage.
    fn read(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), ErrorCode>;

    /// Write `length` bytes starting at address `address` from the provided
    /// buffer. The buffer must be at least `length` bytes long. This address
    /// must be in the address space of the physical storage.
    fn write(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), ErrorCode>;
}

/// Client interface for nonvolatile storage.
pub trait NonvolatileStorageClient {
    /// `read_done` is called when the implementor is finished reading in to the
    /// buffer. The callback returns the buffer and the number of bytes that
    /// were actually read.
    fn read_done(&self, buffer: &'static mut [u8], length: usize);

    /// `write_done` is called when the implementor is finished writing from the
    /// buffer. The callback returns the buffer and the number of bytes that
    /// were actually written.
    fn write_done(&self, buffer: &'static mut [u8], length: usize);
}
