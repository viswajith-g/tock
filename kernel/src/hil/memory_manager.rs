// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Interface the memory manager.

pub trait MemoryManager {
    fn free(&self, required_size: usize) -> Option<&'static mut [u8]>;
}