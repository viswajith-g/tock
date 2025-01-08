// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Test that an Alarm implementation is working. Depends on a working
//! UART and debug! macro.
//!
//! Author: Philip Levis <plevis@google.com>
//! Last Modified: 1/10/2020
use core::cell::Cell;
use kernel::debug;
use kernel::hil::time::{Alarm, AlarmClient, Frequency, Ticks};

pub struct TestAlarm<'a, A: Alarm<'a>> {
    alarm: &'a A,
    ms: Cell<u32>,
}

impl<'a, A: Alarm<'a>> TestAlarm<'a, A> {
    pub fn new(alarm: &'a A) -> TestAlarm<'a, A> {
        TestAlarm {
            alarm,
            ms: Cell::new(0),
        }
    }

    pub fn run(&self) {
        debug!("Starting alarms.");
        self.ms.set(10000);
        self.set_next_alarm(10000);
    }

    fn set_next_alarm(&self, ms: u32) {
        self.ms.set(ms);
        let now: A::Ticks = self.alarm.now();
        let freq: u64 = <A::Frequency>::frequency() as u64;
        let lticks: u64 = ms as u64 * freq;
        let ticks: u32 = (lticks / 1000) as u32;
        debug!("Setting alarm to {} + {}", now.into_u32(), ticks);
        self.alarm.set_alarm(now, A::Ticks::from(ticks));
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for TestAlarm<'a, A> {
    fn alarm(&self) {
        // Generate a new interval that's irregular
        let now: A::Ticks = self.alarm.now();
        let ticks: u32 = 10 + ((now.into_u32() + 137) % 757);
        self.set_next_alarm(ticks);
    }
}
