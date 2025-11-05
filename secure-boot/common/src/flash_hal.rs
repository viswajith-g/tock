// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2025.

//! Flash HAL (nRF52840 specific for now. Should be a HIL eventually)

use crate::error::BootError;

/// nRF52840 NVMC base address
const NVMC_BASE: usize = 0x4001_E000;

/// Registers
const NVMC_READY: *const u32 = (NVMC_BASE + 0x400) as *const u32;
const NVMC_CONFIG: *mut u32 = (NVMC_BASE + 0x504) as *mut u32;
const NVMC_ERASEPAGE: *mut u32 = (NVMC_BASE + 0x508) as *mut u32;

/// Configuration values
const CONFIG_REN: u32 = 0; // Read-only
const CONFIG_WEN: u32 = 1; // Write enable
const CONFIG_EEN: u32 = 2; // Erase enable

/// nRF52840 page size
pub const PAGE_SIZE: usize = 4096;

/// Flash HAL
pub struct FlashHal;

impl FlashHal {
    /// Wait for NVMC to be ready
    #[inline]
    fn wait_ready() {
        unsafe {
            while core::ptr::read_volatile(NVMC_READY) == 0 {}
        }
    }
    
    /// Enable erase mode
    #[inline]
    fn enable_erase() {
        unsafe {
            core::ptr::write_volatile(NVMC_CONFIG, CONFIG_EEN);
        }
        Self::wait_ready();
    }
    
    /// Enable write mode
    #[inline]
    fn enable_write() {
        unsafe {
            core::ptr::write_volatile(NVMC_CONFIG, CONFIG_WEN);
        }
        Self::wait_ready();
    }
    
    /// Set read-only mode
    #[inline]
    fn set_readonly() {
        unsafe {
            core::ptr::write_volatile(NVMC_CONFIG, CONFIG_REN);
        }
        Self::wait_ready();
    }
    
    /// Erase a single page
    /// 
    /// Address must be page-aligned
    pub fn erase_page(address: usize) -> Result<(), BootError> {
        if address % PAGE_SIZE != 0 {
            return Err(BootError::FlashOperationFailed);
        }
        
        Self::enable_erase();
        
        unsafe {
            core::ptr::write_volatile(NVMC_ERASEPAGE, address as u32);
        }
        Self::wait_ready();
        
        Self::set_readonly();
        
        Ok(())
    }
    
    /// Erase multiple pages
    /// 
    /// Start address must be page-aligned
    pub fn erase_pages(start_address: usize, num_pages: usize) -> Result<(), BootError> {
        if start_address % PAGE_SIZE != 0 {
            return Err(BootError::FlashOperationFailed);
        }
        
        Self::enable_erase();
        
        for i in 0..num_pages {
            let page_addr = start_address + (i * PAGE_SIZE);
            unsafe {
                core::ptr::write_volatile(NVMC_ERASEPAGE, page_addr as u32);
            }
            Self::wait_ready();
        }
        
        Self::set_readonly();
        
        Ok(())
    }
    
    /// Write a word to flash
    /// 
    /// Address must be word-aligned
    pub fn write_word(address: usize, word: u32) -> Result<(), BootError> {
        if address % 4 != 0 {
            return Err(BootError::FlashOperationFailed);
        }
        
        Self::enable_write();
        
        unsafe {
            let ptr = address as *mut u32;
            core::ptr::write_volatile(ptr, word);
        }
        Self::wait_ready();
        
        Self::set_readonly();
        
        Ok(())
    }
    
    /// Write a buffer to flash
    /// 
    /// Address must be word-aligned. Buffer is padded to word boundary if needed.
    pub fn write_buffer(address: usize, buffer: &[u8]) -> Result<(), BootError> {
        if address % 4 != 0 {
            return Err(BootError::FlashOperationFailed);
        }
        
        Self::enable_write();
        
        let mut offset = 0;
        while offset < buffer.len() {
            let word = if offset + 4 <= buffer.len() {
                u32::from_le_bytes([
                    buffer[offset],
                    buffer[offset + 1],
                    buffer[offset + 2],
                    buffer[offset + 3],
                ])
            } else {
                // Partial word at end - pad with 0xFF
                let mut bytes = [0xFF; 4];
                for i in 0..(buffer.len() - offset) {
                    bytes[i] = buffer[offset + i];
                }
                u32::from_le_bytes(bytes)
            };
            
            unsafe {
                let ptr = (address + offset) as *mut u32;
                core::ptr::write_volatile(ptr, word);
            }
            Self::wait_ready();
            
            offset += 4;
        }
        
        Self::set_readonly();
        
        Ok(())
    }
}