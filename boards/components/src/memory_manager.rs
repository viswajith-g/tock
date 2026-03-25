// components/src/memory_manager.rs

use core::mem::MaybeUninit;

use kernel::component::Component;

#[macro_export]
macro_rules! memory_manager_component_static {
    () => {{
        kernel::static_buf!(kernel::memory_manager::MemoryManager)
    };};
}

pub struct MemoryManagerComponent {
    app_memory: &'static mut [u8],
    kernel: &'static kernel::Kernel,
}

impl MemoryManagerComponent {
    pub fn new(app_memory: &'static mut [u8], kernel: &'static kernel::Kernel) -> Self {
        Self { app_memory, kernel }
    }
}

impl Component for MemoryManagerComponent {
    type StaticInput = &'static mut MaybeUninit<kernel::memory_manager::MemoryManager>;
    type Output = &'static kernel::memory_manager::MemoryManager;

    fn finalize(self, s: Self::StaticInput) -> Self::Output {
        s.write(kernel::memory_manager::MemoryManager::new(
            self.app_memory as &[u8],
            self.kernel,
        ))
    }
}