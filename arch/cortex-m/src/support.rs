// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use crate::scb;

#[cfg(any(doc, all(target_arch = "arm", target_os = "none")))]
#[inline(always)]
/// NOP instruction
pub fn nop() {
    use core::arch::asm;
    unsafe {
        asm!("nop", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(any(doc, all(target_arch = "arm", target_os = "none")))]
#[inline(always)]
/// WFI instruction
pub unsafe fn wfi() {
    use core::arch::asm;
    asm!("wfi", options(nomem, preserves_flags));
}

#[cfg(any(doc, all(target_arch = "arm", target_os = "none")))]
pub unsafe fn atomic<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    use core::arch::asm;
    // Set PRIMASK
    asm!("cpsid i", options(nomem, nostack));

    let res = f();

    // Unset PRIMASK
    asm!("cpsie i", options(nomem, nostack));
    res
}

// Mock implementations for tests on Travis-CI.
#[cfg(not(any(doc, all(target_arch = "arm", target_os = "none"))))]
/// NOP instruction (mock)
pub fn nop() {
    unimplemented!()
}

#[cfg(not(any(doc, all(target_arch = "arm", target_os = "none"))))]
/// WFI instruction (mock)
pub unsafe fn wfi() {
    unimplemented!()
}

#[cfg(not(any(doc, all(target_arch = "arm", target_os = "none"))))]
pub unsafe fn atomic<F, R>(_f: F) -> R
where
    F: FnOnce() -> R,
{
    unimplemented!()
}

pub fn reset() -> ! {
    unsafe {
        scb::reset();
    }
    loop {
        // This is required to avoid the empty loop clippy
        // warning #[warn(clippy::empty_loop)]
        nop();
    }
}
