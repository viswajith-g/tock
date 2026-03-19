// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Tock kernel for the Nordic Semiconductor nRF52840 development kit (DK).

#![no_std]
#![no_main]
#![deny(missing_docs)]

use kernel::component::Component;
use kernel::debug::PanicResources;
use kernel::hil::led::LedLow;
use kernel::hil::time::Counter;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::process::ProcessArray;
use kernel::process::ProcessLoadingAsync;
use kernel::utilities::single_thread_value::SingleThreadValue;
use kernel::{capabilities, create_capability, static_init};
use nrf52840::gpio::Pin;
use nrf52840::interrupt_service::Nrf52840DefaultPeripherals;
use nrf52_components::{UartChannel, UartPins};

// The nRF52840DK LEDs (see back of board)
const LED1_PIN: Pin = Pin::P0_13;
const LED2_PIN: Pin = Pin::P0_14;
const LED3_PIN: Pin = Pin::P0_15;
const LED4_PIN: Pin = Pin::P0_16;

// The nRF52840DK buttons (see back of board)
const BUTTON1_PIN: Pin = Pin::P0_11;
const BUTTON2_PIN: Pin = Pin::P0_12;
const BUTTON3_PIN: Pin = Pin::P0_24;
const BUTTON4_PIN: Pin = Pin::P0_25;
const BUTTON_RST_PIN: Pin = Pin::P0_18;
const GPIO_PIN: Pin = Pin::P0_26;

const UART_RTS: Option<Pin> = Some(Pin::P0_05);
const UART_TXD: Pin = Pin::P0_06;
const UART_CTS: Option<Pin> = Some(Pin::P0_07);
const UART_RXD: Pin = Pin::P0_08;

/// Debug Writer
pub mod io;

// State for loading and holding applications.
// How should the kernel respond when a process faults.
const FAULT_RESPONSE: capsules_system::process_policies::PanicFaultPolicy =
    capsules_system::process_policies::PanicFaultPolicy {};

// Number of concurrent processes this platform supports.
const NUM_PROCS: usize = 8;

type ChipHw = nrf52840::chip::NRF52<'static, Nrf52840DefaultPeripherals<'static>>;
type ProcessPrinter = capsules_system::process_printer::ProcessPrinterText;

/// Resources for when a board panics used by io.rs.
static PANIC_RESOURCES: SingleThreadValue<PanicResources<ChipHw, ProcessPrinter>> =
    SingleThreadValue::new(PanicResources::new());

kernel::stack_size! {0x2000}

//------------------------------------------------------------------------------
// SYSCALL DRIVER TYPE DEFINITIONS
//------------------------------------------------------------------------------

type AlarmDriver = components::alarm::AlarmDriverComponentType<nrf52840::rtc::Rtc<'static>>;

type NonVolatilePages = components::dynamic_binary_storage::NVPages<nrf52840::nvmc::Nvmc>;
type DynamicBinaryStorage<'a> = kernel::dynamic_binary_storage::SequentialDynamicBinaryStorage<
    'static,
    'static,
    nrf52840::chip::NRF52<'a, Nrf52840DefaultPeripherals<'a>>,
    kernel::process::ProcessStandardDebugFull,
    NonVolatilePages,
>;

type SchedulerInUse = components::sched::round_robin::RoundRobinComponentType;

/// Supported drivers by the platform
pub struct Platform {
    console: &'static capsules_core::console::Console<'static>,
    button: &'static capsules_core::button::Button<'static, nrf52840::gpio::GPIOPin<'static>>,
    adc: &'static capsules_core::adc::AdcDedicated<'static, nrf52840::adc::Adc<'static>>,
    led: &'static capsules_core::led::LedDriver<
        'static,
        kernel::hil::led::LedLow<'static, nrf52840::gpio::GPIOPin<'static>>,
        4,
    >,
    gpio: &'static capsules_core::gpio::GPIO<'static, nrf52840::gpio::GPIOPin<'static>>,
    alarm: &'static AlarmDriver,
    scheduler: &'static SchedulerInUse,
    systick: cortexm4::systick::SysTick,
    processes: &'static ProcessArray<NUM_PROCS>,
    dynamic_app_loader: &'static capsules_extra::app_loader::AppLoader<
        DynamicBinaryStorage<'static>,
        DynamicBinaryStorage<'static>,
    >,
}

impl SyscallDriverLookup for Platform {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::syscall::SyscallDriver>) -> R,
    {
        match driver_num {
            capsules_core::console::DRIVER_NUM => f(Some(self.console)),
            capsules_core::alarm::DRIVER_NUM => f(Some(self.alarm)),
            capsules_core::led::DRIVER_NUM => f(Some(self.led)),
            capsules_core::gpio::DRIVER_NUM => f(Some(self.gpio)),
            capsules_core::button::DRIVER_NUM => f(Some(self.button)),
            capsules_core::adc::DRIVER_NUM => f(Some(self.adc)),
            capsules_extra::app_loader::DRIVER_NUM => f(Some(self.dynamic_app_loader)),
            _ => f(None),
        }
    }
}

/// This is in a separate, inline(never) function so that its stack frame is
/// removed when this function returns. Otherwise, the stack space used for
/// these static_inits is wasted.
#[inline(never)]
unsafe fn create_peripherals() -> &'static mut Nrf52840DefaultPeripherals<'static> {
    let ieee802154_ack_buf = static_init!(
        [u8; nrf52840::ieee802154_radio::ACK_BUF_SIZE],
        [0; nrf52840::ieee802154_radio::ACK_BUF_SIZE]
    );
    // Initialize chip peripheral drivers
    let nrf52840_peripherals = static_init!(
        Nrf52840DefaultPeripherals,
        Nrf52840DefaultPeripherals::new(ieee802154_ack_buf)
    );

    nrf52840_peripherals
}

impl KernelResources<nrf52840::chip::NRF52<'static, Nrf52840DefaultPeripherals<'static>>>
    for Platform
{
    type SyscallDriverLookup = Self;
    type SyscallFilter = ();
    type ProcessFault = ();
    type Scheduler = SchedulerInUse;
    type SchedulerTimer = cortexm4::systick::SysTick;
    type WatchDog = ();
    type ContextSwitchCallback = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        self
    }
    fn syscall_filter(&self) -> &Self::SyscallFilter {
        &()
    }
    fn process_fault(&self) -> &Self::ProcessFault {
        &()
    }
    fn scheduler(&self) -> &Self::Scheduler {
        self.scheduler
    }
    fn scheduler_timer(&self) -> &Self::SchedulerTimer {
        &self.systick
    }
    fn watchdog(&self) -> &Self::WatchDog {
        &()
    }
    fn context_switch_callback(&self) -> &Self::ContextSwitchCallback {
        &()
    }
}

impl kernel::process::ProcessLoadingAsyncClient for Platform {
    fn process_loaded(&self, _result: Result<(), kernel::process::ProcessLoadError>) {}

    fn process_loading_finished(&self) {
        kernel::debug!("Processes Loaded at Main:");

        for (i, proc) in self.processes.as_slice().iter().enumerate() {
            proc.get().map(|p| {
                kernel::debug!("[{}] {}", i, p.get_process_name());
                kernel::debug!("    ShortId: {}", p.short_app_id());
            });
        }
    }
}

// ---------------------------------------------------------------------------
// QSPI helpers — all register access via raw volatile pointer writes.
// QSPI peripheral base address on nRF52840.
// ---------------------------------------------------------------------------

/// Return a raw mutable pointer to a QSPI register at the given byte offset.
unsafe fn qspi_reg(offset: usize) -> *mut u32 {
    (0x40029000usize + offset) as *mut u32
}

/// Initialise the QSPI peripheral in XIP mode.
/// After this returns, the external flash is visible at 0x12000000.
///
/// Pin mapping matches the onboard MX25R6435F on the nRF52840DK:
///   SCK = P0.17, CSN = P0.19, IO0 = P0.20, IO1 = P0.21,
///   IO2 = P0.22, IO3 = P0.23
// unsafe fn qspi_xip_init() {
//     // ------------------------------------------------------------------
//     // Configure GPIO pins for high-drive strength.
//     // P0 PIN_CNF registers: base 0x50000000, PIN_CNF[n] at 0x700 + n*4.
//     // Value: DIR=output(bit0=1), INPUT=disconnect(bit1=1),
//     //        PULL=none(bits3:2=00), DRIVE=H0H1(bits10:8=011), SENSE=off.
//     // ------------------------------------------------------------------
//     let p0_base = 0x50000000usize;
//     for pin in [17usize, 19, 20, 21, 22, 23] {
//         let pin_cnf = (p0_base + 0x700 + pin * 4) as *mut u32;
//         pin_cnf.write_volatile(
//             (1 << 0) |  // DIR = output
//             (1 << 1) |  // INPUT = disconnect
//             (3 << 8),   // DRIVE = H0H1 (high drive)
//         );
//     }

//     // ------------------------------------------------------------------
//     // Write PSEL registers (pin select).
//     // Bit 31 must be 0 (connected). Bits 4:0 = pin number.
//     // Port 0 → bit 5 = 0 (implicit).
//     // ------------------------------------------------------------------
//     qspi_reg(0x508).write_volatile(17); // PSEL.SCK
//     qspi_reg(0x50C).write_volatile(19); // PSEL.CSN
//     qspi_reg(0x514).write_volatile(20); // PSEL.IO0
//     qspi_reg(0x518).write_volatile(21); // PSEL.IO1
//     qspi_reg(0x51C).write_volatile(22); // PSEL.IO2
//     qspi_reg(0x520).write_volatile(23); // PSEL.IO3

//     // ------------------------------------------------------------------
//     // IFCONFIG0 (0x524) — protocol configuration.
//     // READOC  bits 2:0 = 0b011 → READ4IO  (quad I/O read, opcode 0xEB)
//     // WRITEOC bits 5:3 = 0b011 → PP4IO    (quad I/O page program)
//     // ADDRMODE bit  6  = 0     → 24-bit addressing
//     // DPMENABLE bit 7  = 0     → deep power-mode disabled
//     // ------------------------------------------------------------------
//     qspi_reg(0x524).write_volatile(
//         (0x3 << 0) | // READOC  = READ4IO
//         (0x3 << 3) | // WRITEOC = PP4IO
//         (0x0 << 6) | // ADDRMODE = 24-bit
//         (0x0 << 7),  // DPMENABLE = off
//     );

//     // ------------------------------------------------------------------
//     // IFCONFIG1 (0x544) — timing configuration.
//     // SCKDELAY bits 7:0  = 0x80  (cycles CS must stay high between
//     //                             transfers; 0x80 is safe for MX25R6435F)
//     // DPMEN    bit  24   = 0     (deep power-mode entry disabled)
//     // SPIMODE  bit  25   = 0     (MODE0: CPOL=0, CPHA=0)
//     // SCKFREQ  bits 31:28= 7     → fQSPI = 32 MHz / (7+1) = 4 MHz
//     //                                (conservative; raise to 2–3 once working)
//     // ------------------------------------------------------------------
//     qspi_reg(0x544).write_volatile(
//         (0x80u32 <<  0) | // SCKDELAY
//         (0x0  << 24) |    // DPMEN
//         (0x0  << 25) |    // SPIMODE = MODE0
//         (0x7  << 28),     // SCKFREQ → 4 MHz
//     );

//     // ------------------------------------------------------------------
//     // XIPOFFSET (0x540) — flash byte offset for the XIP window.
//     // 0 → CPU address 0x12000000 maps to flash offset 0x000000.
//     // ------------------------------------------------------------------
//     qspi_reg(0x540).write_volatile(0x00000000); // XIPOFFSET

//     // ------------------------------------------------------------------
//     // ENABLE (0x500) = 1 — enable the QSPI peripheral.
//     // ------------------------------------------------------------------
//     qspi_reg(0x500).write_volatile(1);

//     // ------------------------------------------------------------------
//     // TASKS_ACTIVATE (0x000) — start the peripheral.
//     // Clear EVENTS_READY first, then trigger, then poll until set.
//     // ------------------------------------------------------------------
//     qspi_reg(0x100).write_volatile(0); // clear EVENTS_READY
//     qspi_reg(0x000).write_volatile(1); // TASKS_ACTIVATE
//     while qspi_reg(0x100).read_volatile() == 0 {}
//     qspi_reg(0x100).write_volatile(0); // clear EVENTS_READY

//     // ------------------------------------------------------------------
//     // MX25R6435F: enable Quad mode via Write Status Register.
//     // The chip powers up in single-SPI mode; READ4IO won't work until
//     // the QE bit (Status Register 2, bit 1) is set.
//     //
//     // Sequence:
//     //   WREN (0x06)          — enable write
//     //   WRSR (0x01) + 3 bytes — SR1=0x00, SR2=0x02 (QE=1), SR3=0x00
//     // ------------------------------------------------------------------
//     qspi_send_custom_instruction(0x06, &[], &mut []); // WREN
//     qspi_send_custom_instruction(0x01, &[0x00, 0x02, 0x00], &mut []); // WRSR: set QE

//     // Wait for the flash to finish the status register write (WIP polling).
//     // Poll Read Status Register 1 (0x05) until WIP bit (bit 0) clears.
//     loop {
//         // Read 1 byte back: send RDSR, get SR1 in CINSTRDAT0 bits 15:8.
//         qspi_reg(0x55C).write_volatile(0);
//         qspi_reg(0x558).write_volatile(
//             (0x05u32) |  // opcode RDSR
//             (2u32 << 8)  // LENGTH = 2 (opcode + 1 rx byte)
//         );
//         while qspi_reg(0x100).read_volatile() == 0 {}
//         qspi_reg(0x100).write_volatile(0);

//         let sr1 = (qspi_reg(0x55C).read_volatile() >> 8) & 0xFF;
//         if sr1 & 0x01 == 0 {
//             break; // WIP cleared — write complete
//         }
//     }

//     let first_word = core::ptr::read_volatile(0x12000000 as *const u32);
//     kernel::debug!("QSPI XIP init done. [0x12000000] = {:#010x}", first_word);
// }

// unsafe fn qspi_xip_init() {
//     let p0_base = 0x50000000usize;
//     for pin in [17usize, 19, 20, 21, 22, 23] {
//         let pin_cnf = (p0_base + 0x700 + pin * 4) as *mut u32;
//         pin_cnf.write_volatile((1 << 0) | (1 << 1) | (3 << 8));
//     }

//     qspi_reg(0x508).write_volatile(17);
//     qspi_reg(0x50C).write_volatile(19);
//     qspi_reg(0x514).write_volatile(20);
//     qspi_reg(0x518).write_volatile(21);
//     qspi_reg(0x51C).write_volatile(22);
//     qspi_reg(0x520).write_volatile(23);

//     qspi_reg(0x524).write_volatile((0x3 << 0) | (0x3 << 3) | (0x0 << 6) | (0x0 << 7));
//     qspi_reg(0x544).write_volatile((0x80u32 << 0) | (0x0 << 24) | (0x0 << 25) | (0x7 << 28));
//     qspi_reg(0x540).write_volatile(0x00000000);
//     qspi_reg(0x500).write_volatile(1);

//     qspi_reg(0x100).write_volatile(0);
//     qspi_reg(0x000).write_volatile(1); // TASKS_ACTIVATE

//     // Timeout instead of infinite wait
//     let mut i = 0u32;
//     while qspi_reg(0x100).read_volatile() == 0 {
//         i += 1;
//         if i > 2_000_000 {
//             // Store a sentinel so we can check after debug writer is up
//             core::ptr::write_volatile(0x20000000 as *mut u32, 0xDEAD0001);
//             break;
//         }
//     }

//     if i <= 2_000_000 {
//         qspi_reg(0x100).write_volatile(0);
//         core::ptr::write_volatile(0x20000000 as *mut u32, 0x900DD00D);
//     }
//     // Don't do the custom instructions yet — just get past activate first
// }

unsafe fn qspi_send_custom_instruction(opcode: u8, tx: &[u8], _rx: &mut [u8]) -> bool {
    let mut dat0: u32 = 0;
    for (i, b) in tx.iter().take(4).enumerate() {
        dat0 |= (*b as u32) << (i * 8);
    }
    qspi_reg(0x55C).write_volatile(dat0);

    let length: u32 = 1 + tx.len().min(4) as u32;
    qspi_reg(0x558).write_volatile((opcode as u32) | (length << 8));

    let mut i = 0u32;
    while qspi_reg(0x100).read_volatile() == 0 {
        i += 1;
        if i > 2_000_000 {
            kernel::debug!("CINSTR timeout: opcode {:#04x}", opcode);
            qspi_reg(0x100).write_volatile(0);
            return false;
        }
    }
    qspi_reg(0x100).write_volatile(0);
    true
}

unsafe fn qspi_xip_init() {
    let p0_base = 0x50000000usize;
    for pin in [17usize, 19, 20, 21, 22, 23] {
        let pin_cnf = (p0_base + 0x700 + pin * 4) as *mut u32;
        pin_cnf.write_volatile((1 << 0) | (1 << 1) | (3 << 8));
    }

    qspi_reg(0x508).write_volatile(17);
    qspi_reg(0x50C).write_volatile(19);
    qspi_reg(0x514).write_volatile(20);
    qspi_reg(0x518).write_volatile(21);
    qspi_reg(0x51C).write_volatile(22);
    qspi_reg(0x520).write_volatile(23);

    qspi_reg(0x524).write_volatile((0x0 << 0) | (0x0 << 3) | (0x0 << 6) | (0x0 << 7));
    // qspi_reg(0x524).write_volatile((0x3 << 0) | (0x3 << 3) | (0x0 << 6) | (0x0 << 7));
    qspi_reg(0x544).write_volatile((0x80u32 << 0) | (0x0 << 24) | (0x0 << 25) | (0x7 << 28));
    qspi_reg(0x540).write_volatile(0x00000000);
    qspi_reg(0x500).write_volatile(1);

    qspi_reg(0x100).write_volatile(0);
    qspi_reg(0x000).write_volatile(1); // TASKS_ACTIVATE

    // let mut i = 0u32;
    // while qspi_reg(0x100).read_volatile() == 0 {
    //     i += 1;
    //     if i > 2_000_000 {
    //         core::ptr::write_volatile(0x20000000 as *mut u32, 0xDEAD0001);
    //         kernel::debug!("QSPI activate timed out");
    //         return;
    //     }
    // }
    // qspi_reg(0x100).write_volatile(0);
    // core::ptr::write_volatile(0x20000000 as *mut u32, 0x900DD00D);
    // kernel::debug!("QSPI activate OK");

    // // WREN then WRSR to set QE bit
    // if !qspi_send_custom_instruction(0x06, &[], &mut []) {
    //     kernel::debug!("WREN failed");
    //     return;
    // }
    // kernel::debug!("WREN OK");

    // if !qspi_send_custom_instruction(0x01, &[0x00, 0x02, 0x00], &mut []) {
    //     kernel::debug!("WRSR failed");
    //     return;
    // }
    // kernel::debug!("WRSR OK");

    // // Poll RDSR until WIP clears
    // let mut attempts = 0u32;
    // loop {
    //     qspi_reg(0x55C).write_volatile(0);
    //     qspi_reg(0x558).write_volatile((0x05u32) | (2u32 << 8));

    //     let mut j = 0u32;
    //     while qspi_reg(0x100).read_volatile() == 0 {
    //         j += 1;
    //         if j > 2_000_000 {
    //             kernel::debug!("RDSR timeout");
    //             qspi_reg(0x100).write_volatile(0);
    //             break;
    //         }
    //     }
    //     qspi_reg(0x100).write_volatile(0);

    //     let sr1 = (qspi_reg(0x55C).read_volatile() >> 8) & 0xFF;
    //     kernel::debug!("SR1 = {:#04x}", sr1);
    //     if sr1 & 0x01 == 0 {
    //         kernel::debug!("WIP cleared");
    //         break;
    //     }

    //     attempts += 1;
    //     if attempts > 100 {
    //         kernel::debug!("WIP never cleared after 100 attempts");
    //         break;
    //     }
    // }

    let mut i = 0u32;
    while qspi_reg(0x100).read_volatile() == 0 {
        i += 1;
        if i > 2_000_000 {
            kernel::debug!("QSPI activate timed out");
            return;
        }
    }
    qspi_reg(0x100).write_volatile(0);
    kernel::debug!("QSPI activate OK");

    let first_word = core::ptr::read_volatile(0x12000000 as *const u32);
    kernel::debug!("QSPI[0] = {:#010x}", first_word);
}

/// Main function called after RAM initialized.
#[no_mangle]
pub unsafe fn main() {
    //--------------------------------------------------------------------------
    // INITIAL SETUP
    //--------------------------------------------------------------------------

    // Apply errata fixes and enable interrupts.
    nrf52840::init();

    // Initialize deferred calls very early.
    kernel::deferred_call::initialize_deferred_call_state::<
        <ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider,
    >();

    // Bind global variables to this thread.
    PANIC_RESOURCES.bind_to_thread::<<ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider>();

    // Set up peripheral drivers. Called in separate function to reduce stack
    // usage.
    let nrf52840_peripherals = create_peripherals();

    // Set up circular peripheral dependencies.
    nrf52840_peripherals.init();
    let base_peripherals = &nrf52840_peripherals.nrf52;

    // Choose the channel for serial output. This board can be configured to use
    // either the Segger RTT channel or via UART with traditional TX/RX GPIO
    // pins.
    let uart_channel = UartChannel::Pins(UartPins::new(UART_RTS, UART_TXD, UART_CTS, UART_RXD));

    // Create an array to hold process references.
    let processes = components::process_array::ProcessArrayComponent::new()
        .finalize(components::process_array_component_static!(NUM_PROCS));
    PANIC_RESOURCES.get().map(|resources| {
        resources.processes.put(processes.as_slice());
    });

    // Setup space to store the core kernel data structure.
    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(processes.as_slice()));

    // Create (and save for panic debugging) a chip object to setup low-level
    // resources (e.g. MPU, systick).
    let chip = static_init!(
        nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>,
        nrf52840::chip::NRF52::new(nrf52840_peripherals)
    );
    PANIC_RESOURCES.get().map(|resources| {
        resources.chip.put(chip);
    });

    // Do nRF configuration and setup. This is shared code with other nRF-based
    // platforms.
    nrf52_components::startup::NrfStartupComponent::new(
        false,
        BUTTON_RST_PIN,
        nrf52840::uicr::Regulator0Output::DEFAULT,
        &base_peripherals.nvmc,
    )
    .finalize(());

    //--------------------------------------------------------------------------
    // CAPABILITIES
    //--------------------------------------------------------------------------

    // Create capabilities that the board needs to call certain protected kernel
    // functions.
    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);

    //--------------------------------------------------------------------------
    // LEDs
    //--------------------------------------------------------------------------

    let led = components::led::LedsComponent::new().finalize(components::led_component_static!(
        LedLow<'static, nrf52840::gpio::GPIOPin>,
        LedLow::new(&nrf52840_peripherals.gpio_port[LED1_PIN]),
        LedLow::new(&nrf52840_peripherals.gpio_port[LED2_PIN]),
        LedLow::new(&nrf52840_peripherals.gpio_port[LED3_PIN]),
        LedLow::new(&nrf52840_peripherals.gpio_port[LED4_PIN]),
    ));

    //--------------------------------------------------------------------------
    // TIMER
    //--------------------------------------------------------------------------

    let rtc = &base_peripherals.rtc;
    let _ = rtc.start();
    let mux_alarm = components::alarm::AlarmMuxComponent::new(rtc)
        .finalize(components::alarm_mux_component_static!(nrf52840::rtc::Rtc));
    let alarm = components::alarm::AlarmDriverComponent::new(
        board_kernel,
        capsules_core::alarm::DRIVER_NUM,
        mux_alarm,
    )
    .finalize(components::alarm_component_static!(nrf52840::rtc::Rtc));

    //--------------------------------------------------------------------------
    // UART & CONSOLE & DEBUG
    //--------------------------------------------------------------------------

    let uart_channel = nrf52_components::UartChannelComponent::new(
        uart_channel,
        mux_alarm,
        &base_peripherals.uarte0,
    )
    .finalize(nrf52_components::uart_channel_component_static!(
        nrf52840::rtc::Rtc
    ));

    // Virtualize the UART channel for the console and for kernel debug.
    let uart_mux = components::console::UartMuxComponent::new(uart_channel, 115200)
        .finalize(components::uart_mux_component_static!());

    // Setup the serial console for userspace.
    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::console_component_static!());

    // Tool for displaying information about processes.
    let process_printer = components::process_printer::ProcessPrinterTextComponent::new()
        .finalize(components::process_printer_text_component_static!());
    PANIC_RESOURCES.get().map(|resources| {
        resources.printer.put(process_printer);
    });

    // Create the process console, an interactive terminal for managing
    // processes.
    let pconsole = components::process_console::ProcessConsoleComponent::new(
        board_kernel,
        uart_mux,
        mux_alarm,
        process_printer,
        Some(cortexm4::support::reset),
    )
    .finalize(components::process_console_component_static!(
        nrf52840::rtc::Rtc<'static>
    ));

    // Create the debugger object that handles calls to `debug!()`.
    components::debug_writer::DebugWriterComponent::new::<
        <ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider,
    >(
        uart_mux,
        create_capability!(capabilities::SetDebugWriterCapability),
    )
    .finalize(components::debug_writer_component_static!());

    //--------------------------------------------------------------------------
    // BUTTONS
    //--------------------------------------------------------------------------

    let button = components::button::ButtonComponent::new(
        board_kernel,
        capsules_core::button::DRIVER_NUM,
        components::button_component_helper!(
            nrf52840::gpio::GPIOPin,
            (
                &nrf52840_peripherals.gpio_port[BUTTON1_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            ),
            (
                &nrf52840_peripherals.gpio_port[BUTTON2_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            ),
            (
                &nrf52840_peripherals.gpio_port[BUTTON3_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            ),
            (
                &nrf52840_peripherals.gpio_port[BUTTON4_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            )
        ),
    )
    .finalize(components::button_component_static!(
        nrf52840::gpio::GPIOPin
    ));

    //--------------------------------------------------------------------------
    // ADC
    //--------------------------------------------------------------------------

    let adc_channels = static_init!(
        [nrf52840::adc::AdcChannelSetup; 6],
        [
            nrf52840::adc::AdcChannelSetup::new(nrf52840::adc::AdcChannel::AnalogInput1),
            nrf52840::adc::AdcChannelSetup::new(nrf52840::adc::AdcChannel::AnalogInput2),
            nrf52840::adc::AdcChannelSetup::new(nrf52840::adc::AdcChannel::AnalogInput4),
            nrf52840::adc::AdcChannelSetup::new(nrf52840::adc::AdcChannel::AnalogInput5),
            nrf52840::adc::AdcChannelSetup::new(nrf52840::adc::AdcChannel::AnalogInput6),
            nrf52840::adc::AdcChannelSetup::new(nrf52840::adc::AdcChannel::AnalogInput7),
        ]
    );
    let adc = components::adc::AdcDedicatedComponent::new(
        &base_peripherals.adc,
        adc_channels,
        board_kernel,
        capsules_core::adc::DRIVER_NUM,
    )
    .finalize(components::adc_dedicated_component_static!(
        nrf52840::adc::Adc
    ));

    //--------------------------------------------------------------------------
    // NRF CLOCK SETUP
    //--------------------------------------------------------------------------

    nrf52_components::NrfClockComponent::new(&base_peripherals.clock).finalize(());

    //--------------------------------------------------------------------------
    // GPIO SETUP
    //--------------------------------------------------------------------------
    let gpio = components::gpio::GpioComponent::new(
        board_kernel,
        capsules_core::gpio::DRIVER_NUM,
        components::gpio_component_helper!(
            nrf52840::gpio::GPIOPin,
            0 => &nrf52840_peripherals.gpio_port[GPIO_PIN]
        ),
    )
    .finalize(components::gpio_component_static!(
        nrf52840::gpio::GPIOPin
    ));

    //--------------------------------------------------------------------------
    // QSPI XIP INIT
    //--------------------------------------------------------------------------

    kernel::debug!("Before qspi init");
    qspi_xip_init();
    let sentinel = core::ptr::read_volatile(0x20000000 as *const u32);
    kernel::debug!("QSPI activate result: {:#010x}", sentinel);
    let first_word = core::ptr::read_volatile(0x12000000 as *const u32);
    kernel::debug!("QSPI First Word = {:#010x}", first_word);

    //--------------------------------------------------------------------------
    // Credential Checking
    //--------------------------------------------------------------------------

    // Create the credential checker.
    let checking_policy = components::appid::checker_null::AppCheckerNullComponent::new()
        .finalize(components::app_checker_null_component_static!());

    // Create the AppID assigner.
    let assigner = components::appid::assigner_tbf::AppIdAssignerTbfHeaderComponent::new()
        .finalize(components::appid_assigner_tbf_header_component_static!());

    // Create the process checking machine.
    let checker = components::appid::checker::ProcessCheckerMachineComponent::new(checking_policy)
        .finalize(components::process_checker_machine_component_static!());

    //--------------------------------------------------------------------------
    // STORAGE PERMISSIONS
    //--------------------------------------------------------------------------

    let storage_permissions_policy =
        components::storage_permissions::null::StoragePermissionsNullComponent::new().finalize(
            components::storage_permissions_null_component_static!(
                nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>,
                kernel::process::ProcessStandardDebugFull,
            ),
        );

    // Point app_flash at the QSPI XIP window instead of internal flash.
    // The process loader will walk this slice looking for valid TBF headers.

    // app_memory still comes from internal SRAM via the linker script.
    // These symbols are defined in the standard Tock linker script.
    extern "C" {
        /// Beginning of the ROM region containing app images.
        static _sapps: u8;
        /// End of the ROM region containing app images.
        static _eapps: u8;
        /// Beginning of the RAM region for app memory.
        static mut _sappmem: u8;
        /// End of the RAM region for app memory.
        static _eappmem: u8;
    }

    let app_flash = core::slice::from_raw_parts(
        core::ptr::addr_of!(_sapps),
        core::ptr::addr_of!(_eapps) as usize - core::ptr::addr_of!(_sapps) as usize,
    );
    let app_memory = core::slice::from_raw_parts_mut(
        core::ptr::addr_of_mut!(_sappmem),
        core::ptr::addr_of!(_eappmem) as usize - core::ptr::addr_of!(_sappmem) as usize,
    );

    // Create and start the asynchronous process loader.
    let loader = components::loader::sequential::ProcessLoaderSequentialComponent::new(
        checker,
        board_kernel,
        chip,
        &FAULT_RESPONSE,
        assigner,
        storage_permissions_policy,
        app_flash,
        app_memory,
    )
    .finalize(components::process_loader_sequential_component_static!(
        nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>,
        kernel::process::ProcessStandardDebugFull,
        NUM_PROCS
    ));

    //--------------------------------------------------------------------------
    // Dynamic App Loading
    //--------------------------------------------------------------------------

    // Create the dynamic binary flasher.
    let dynamic_binary_storage =
        components::dynamic_binary_storage::SequentialBinaryStorageComponent::new(
            &base_peripherals.nvmc,
            loader,
        )
        .finalize(components::sequential_binary_storage_component_static!(
            nrf52840::nvmc::Nvmc,
            nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>,
            kernel::process::ProcessStandardDebugFull,
        ));

    // Create the dynamic app loader capsule.
    let dynamic_app_loader = components::app_loader::AppLoaderComponent::new(
        board_kernel,
        capsules_extra::app_loader::DRIVER_NUM,
        dynamic_binary_storage,
        dynamic_binary_storage,
    )
    .finalize(components::app_loader_component_static!(
        DynamicBinaryStorage<'static>,
        DynamicBinaryStorage<'static>,
    ));

    //--------------------------------------------------------------------------
    // PLATFORM SETUP, SCHEDULER, AND START KERNEL LOOP
    //--------------------------------------------------------------------------

    let scheduler = components::sched::round_robin::RoundRobinComponent::new(processes)
        .finalize(components::round_robin_component_static!(NUM_PROCS));

    let platform = static_init!(
        Platform,
        Platform {
            console,
            button,
            adc,
            led,
            gpio,
            alarm,
            scheduler,
            systick: cortexm4::systick::SysTick::new_with_calibration(64000000),
            processes,
            dynamic_app_loader,
        }
    );
    loader.set_client(platform);

    let _ = pconsole.start();

    board_kernel.kernel_loop(
        platform,
        chip,
        None::<&kernel::ipc::IPC<0>>,
        &main_loop_capability,
    );
}