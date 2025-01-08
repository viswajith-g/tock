// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Components for the Touch Panel.
//!
//! Usage
//! -----
//!
//! Touch
//!
//! ```rust
//! // Just Touch
//! let touch =
//!     components::touch::TouchComponent::new(board_kernel, ts, None, Some(screen))
//!         .finalize(components::touch_component_static!());
//!
//! // With Gesture
//! let touch =
//!     components::touch::TouchComponent::new(board_kernel, ts, Some(ts), Some(screen))
//!         .finalize(components::touch_component_static!());
//! ```
//!
//! Multi Touch
//!
//! ```rust
//! // Just Multi Touch
//! let touch =
//!     components::touch::MultiTouchComponent::new(board_kernel, ts, None, Some(screen))
//!         .finalize(components::touch_component_static!());
//!
//! // With Gesture
//! let touch =
//!     components::touch::MultiTouchComponent::new(board_kernel, ts, Some(ts), Some(screen))
//!         .finalize(components::touch_component_static!());
//! ```
use capsules_extra::touch::Touch;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;

#[macro_export]
macro_rules! touch_component_static {
    () => {{
        kernel::static_buf!(capsules_extra::touch::Touch<'static>)
    };};
}

pub struct TouchComponent {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    touch: &'static dyn kernel::hil::touch::Touch<'static>,
    gesture: Option<&'static dyn kernel::hil::touch::Gesture<'static>>,
    screen: Option<&'static dyn kernel::hil::screen::Screen<'static>>,
}

impl TouchComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        touch: &'static dyn kernel::hil::touch::Touch<'static>,
        gesture: Option<&'static dyn kernel::hil::touch::Gesture<'static>>,
        screen: Option<&'static dyn kernel::hil::screen::Screen<'static>>,
    ) -> TouchComponent {
        TouchComponent {
            board_kernel,
            driver_num,
            touch,
            gesture,
            screen,
        }
    }
}

impl Component for TouchComponent {
    type StaticInput = &'static mut MaybeUninit<Touch<'static>>;
    type Output = &'static capsules_extra::touch::Touch<'static>;

    fn finalize(self, static_input: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let grant_touch = self.board_kernel.create_grant(self.driver_num, &grant_cap);

        let touch = static_input.write(capsules_extra::touch::Touch::new(
            Some(self.touch),
            None,
            self.screen,
            grant_touch,
        ));

        kernel::hil::touch::Touch::set_client(self.touch, touch);
        if let Some(gesture) = self.gesture {
            kernel::hil::touch::Gesture::set_client(gesture, touch);
        }

        touch
    }
}

pub struct MultiTouchComponent {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    multi_touch: &'static dyn kernel::hil::touch::MultiTouch<'static>,
    gesture: Option<&'static dyn kernel::hil::touch::Gesture<'static>>,
    screen: Option<&'static dyn kernel::hil::screen::Screen<'static>>,
}

impl MultiTouchComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        multi_touch: &'static dyn kernel::hil::touch::MultiTouch<'static>,
        gesture: Option<&'static dyn kernel::hil::touch::Gesture<'static>>,
        screen: Option<&'static dyn kernel::hil::screen::Screen>,
    ) -> MultiTouchComponent {
        MultiTouchComponent {
            board_kernel,
            driver_num,
            multi_touch,
            gesture,
            screen,
        }
    }
}

impl Component for MultiTouchComponent {
    type StaticInput = &'static mut MaybeUninit<Touch<'static>>;
    type Output = &'static capsules_extra::touch::Touch<'static>;

    fn finalize(self, static_input: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let grant_touch = self.board_kernel.create_grant(self.driver_num, &grant_cap);

        let touch = static_input.write(capsules_extra::touch::Touch::new(
            None,
            Some(self.multi_touch),
            self.screen,
            grant_touch,
        ));

        kernel::hil::touch::MultiTouch::set_client(self.multi_touch, touch);
        if let Some(gesture) = self.gesture {
            kernel::hil::touch::Gesture::set_client(gesture, touch);
        }

        touch
    }
}
