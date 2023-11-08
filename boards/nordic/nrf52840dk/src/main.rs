// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Tock kernel for the Nordic Semiconductor nRF52840 development kit (DK).
//!
//! It is based on nRF52840 SoC (Cortex M4 core with a BLE transceiver) with
//! many exported I/O and peripherals.
//!
//! Pin Configuration
//! -------------------
//!
//! ### `GPIO`
//!
//! | #  | Pin   | Ix | Header | Arduino |
//! |----|-------|----|--------|---------|
//! | 0  | P1.01 | 33 | P3 1   | D0      |
//! | 1  | P1.02 | 34 | P3 2   | D1      |
//! | 2  | P1.03 | 35 | P3 3   | D2      |
//! | 3  | P1.04 | 36 | P3 4   | D3      |
//! | 4  | P1.05 | 37 | P3 5   | D4      |
//! | 5  | P1.06 | 38 | P3 6   | D5      |
//! | 6  | P1.07 | 39 | P3 7   | D6      |
//! | 7  | P1.08 | 40 | P3 8   | D7      |
//! | 8  | P1.10 | 42 | P4 1   | D8      |
//! | 9  | P1.11 | 43 | P4 2   | D9      |
//! | 10 | P1.12 | 44 | P4 3   | D10     |
//! | 11 | P1.13 | 45 | P4 4   | D11     |
//! | 12 | P1.14 | 46 | P4 5   | D12     |
//! | 13 | P1.15 | 47 | P4 6   | D13     |
//! | 14 | P0.26 | 26 | P4 9   | D14     |
//! | 15 | P0.27 | 27 | P4 10  | D15     |
//!
//! ### `GPIO` / Analog Inputs
//!
//! | #  | Pin        | Header | Arduino |
//! |----|------------|--------|---------|
//! | 16 | P0.03 AIN1 | P2 1   | A0      |
//! | 17 | P0.04 AIN2 | P2 2   | A1      |
//! | 18 | P0.28 AIN4 | P2 3   | A2      |
//! | 19 | P0.29 AIN5 | P2 4   | A3      |
//! | 20 | P0.30 AIN6 | P2 5   | A4      |
//! | 21 | P0.31 AIN7 | P2 6   | A5      |
//! | 22 | P0.02 AIN0 | P4 8   | AVDD    |
//!
//! ### Onboard Functions
//!
//! | Pin   | Header | Function |
//! |-------|--------|----------|
//! | P0.05 | P6 3   | UART RTS |
//! | P0.06 | P6 4   | UART TXD |
//! | P0.07 | P6 5   | UART CTS |
//! | P0.08 | P6 6   | UART RXT |
//! | P0.11 | P24 1  | Button 1 |
//! | P0.12 | P24 2  | Button 2 |
//! | P0.13 | P24 3  | LED 1    |
//! | P0.14 | P24 4  | LED 2    |
//! | P0.15 | P24 5  | LED 3    |
//! | P0.16 | P24 6  | LED 4    |
//! | P0.18 | P24 8  | Reset    |
//! | P0.19 | P24 9  | SPI CLK  |
//! | P0.20 | P24 10 | SPI MOSI |
//! | P0.21 | P24 11 | SPI MISO |
//! | P0.22 | P24 12 | SPI CS   |
//! | P0.24 | P24 14 | Button 3 |
//! | P0.25 | P24 15 | Button 4 |
//! | P0.26 | P24 16 | I2C SDA  |
//! | P0.27 | P24 17 | I2C SCL  |

#![no_std]
// Disable this attribute when documenting, as a workaround for
// https://github.com/rust-lang/rust/issues/62184.
#![cfg_attr(not(doc), no_main)]
#![deny(missing_docs)]

use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
use capsules_extra::net::ieee802154::MacAddress;
use capsules_extra::net::ipv6::ip_utils::IPAddr;
use kernel::component::Component;
use kernel::hil::led::LedLow;
use kernel::hil::time::Counter;
#[allow(unused_imports)]
use kernel::hil::usb::Client;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::platform::chip::Chip;
use kernel::scheduler::round_robin::RoundRobinSched;
#[allow(unused_imports)]
use kernel::{capabilities, create_capability, debug, debug_gpio, debug_verbose, static_init};
use nrf52840::gpio::Pin;
use nrf52840::interrupt_service::Nrf52840DefaultPeripherals;
use nrf52_components::{self, UartChannel, UartPins};

#[allow(dead_code)]
mod test;

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

const UART_RTS: Option<Pin> = Some(Pin::P0_05);
const UART_TXD: Pin = Pin::P0_06;
const UART_CTS: Option<Pin> = Some(Pin::P0_07);
const UART_RXD: Pin = Pin::P0_08;

const SPI_MOSI: Pin = Pin::P0_20;
const SPI_MISO: Pin = Pin::P0_21;
const SPI_CLK: Pin = Pin::P0_19;
const SPI_CS: Pin = Pin::P0_22;

const SPI_MX25R6435F_CHIP_SELECT: Pin = Pin::P0_17;
const SPI_MX25R6435F_WRITE_PROTECT_PIN: Pin = Pin::P0_22;
const SPI_MX25R6435F_HOLD_PIN: Pin = Pin::P0_23;

/// I2C pins
const I2C_SDA_PIN: Pin = Pin::P0_26;
const I2C_SCL_PIN: Pin = Pin::P0_27;

// Constants related to the configuration of the 15.4 network stack
const PAN_ID: u16 = 0xABCD;
const DST_MAC_ADDR: capsules_extra::net::ieee802154::MacAddress =
    capsules_extra::net::ieee802154::MacAddress::Short(49138);
const DEFAULT_CTX_PREFIX_LEN: u8 = 8; //Length of context for 6LoWPAN compression
const DEFAULT_CTX_PREFIX: [u8; 16] = [0x0 as u8; 16]; //Context for 6LoWPAN Compression

/// Debug Writer
pub mod io;

// Whether to use UART debugging or Segger RTT (USB) debugging.
// - Set to false to use UART.
// - Set to true to use Segger RTT over USB.
const USB_DEBUGGING: bool = true;

// State for loading and holding applications.
// How should the kernel respond when a process faults.
const FAULT_RESPONSE: kernel::process::PanicFaultPolicy = kernel::process::PanicFaultPolicy {};

// Number of concurrent processes this platform supports.
const NUM_PROCS: usize = 8;

static mut PROCESSES: [Option<&'static dyn kernel::process::Process>; NUM_PROCS] =
    [None; NUM_PROCS];

static mut CHIP: Option<&'static nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>> = None;
static mut PROCESS_PRINTER: Option<&'static kernel::process::ProcessPrinterText> = None;

//This variable is used to save initial value of unused sram start address before launching OTA_app
static mut UNUSED_RAM_START_ADDR_INIT_VAL: usize = 0;
//This variable is used to save process index loaded by tockloader, which will be used in loading app by OTA_app
static mut PROCESS_INDEX_INIT_VAL: usize = 0;
//This arrays is used to save start address and length of process, which will be used in checking overlap region between a new app and already loaded apps
static mut PROCESSES_REGION_START_ADDRESS: [usize; NUM_PROCS] = [0, 0, 0, 0, 0, 0, 0, 0];
static mut PROCESSES_REGION_SIZE: [usize; NUM_PROCS] = [0, 0, 0, 0, 0, 0, 0, 0]; 


/// Dummy buffer that causes the linker to reserve enough space for the stack.
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x2000] = [0; 0x2000];

// Function for the process console to use to reboot the board
fn reset() -> ! {
    unsafe {
        cortexm4::scb::reset();
    }
    loop {
        cortexm4::support::nop();
    }
}

/// Supported drivers by the platform
pub struct Platform <C: 'static + Chip> {
    ble_radio: &'static capsules_extra::ble_advertising_driver::BLE<
        'static,
        nrf52840::ble_radio::Radio<'static>,
        VirtualMuxAlarm<'static, nrf52840::rtc::Rtc<'static>>,
    >,
    ieee802154_radio: &'static capsules_extra::ieee802154::RadioDriver<'static>,
    button: &'static capsules_core::button::Button<'static, nrf52840::gpio::GPIOPin<'static>>,
    // pconsole: &'static capsules_core::process_console::ProcessConsole<
    //     'static,
    //     { capsules_core::process_console::DEFAULT_COMMAND_HISTORY_LEN },
    //     VirtualMuxAlarm<'static, nrf52840::rtc::Rtc<'static>>,
    //     components::process_console::Capability,
    // >,
    console: &'static capsules_core::console::Console<'static>,
    gpio: &'static capsules_core::gpio::GPIO<'static, nrf52840::gpio::GPIOPin<'static>>,
    led: &'static capsules_core::led::LedDriver<
        'static,
        kernel::hil::led::LedLow<'static, nrf52840::gpio::GPIOPin<'static>>,
        4,
    >,
    rng: &'static capsules_core::rng::RngDriver<'static>,
    adc: &'static capsules_core::adc::AdcDedicated<'static, nrf52840::adc::Adc<'static>>,
    temp: &'static capsules_extra::temperature::TemperatureSensor<'static>,
    ipc: kernel::ipc::IPC<{ NUM_PROCS as u8 }>,
    analog_comparator: &'static capsules_extra::analog_comparator::AnalogComparator<
        'static,
        nrf52840::acomp::Comparator<'static>,
    >,
    alarm: &'static capsules_core::alarm::AlarmDriver<
        'static,
        capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm<
            'static,
            nrf52840::rtc::Rtc<'static>,
        >,
    >,
    nonvolatile_storage:
        &'static capsules_extra::nonvolatile_storage_driver::NonvolatileStorage<'static>,
    udp_driver: &'static capsules_extra::net::udp::UDPDriver<'static>,
    i2c_master_slave: &'static capsules_core::i2c_master_slave_driver::I2CMasterSlaveDriver<
        'static,
        nrf52840::i2c::TWI<'static>,
    >,
    spi_controller: &'static capsules_core::spi_controller::Spi<
        'static,
        capsules_core::virtualizers::virtual_spi::VirtualSpiMasterDevice<
            'static,
            nrf52840::spi::SPIM<'static>,
        >,
    >,
    scheduler: &'static RoundRobinSched<'static>,
    systick: cortexm4::systick::SysTick,
    process_loader: kernel::process_load_utilities::ProcessLoader<C>,
}

impl <C: 'static + Chip> SyscallDriverLookup for Platform <C> {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::syscall::SyscallDriver>) -> R,
    {
        match driver_num {
            capsules_core::console::DRIVER_NUM => f(Some(self.console)),
            capsules_core::gpio::DRIVER_NUM => f(Some(self.gpio)),
            capsules_core::alarm::DRIVER_NUM => f(Some(self.alarm)),
            capsules_core::led::DRIVER_NUM => f(Some(self.led)),
            capsules_core::button::DRIVER_NUM => f(Some(self.button)),
            capsules_core::rng::DRIVER_NUM => f(Some(self.rng)),
            capsules_core::adc::DRIVER_NUM => f(Some(self.adc)),
            capsules_extra::ble_advertising_driver::DRIVER_NUM => f(Some(self.ble_radio)),
            capsules_extra::ieee802154::DRIVER_NUM => f(Some(self.ieee802154_radio)),
            capsules_extra::temperature::DRIVER_NUM => f(Some(self.temp)),
            capsules_extra::analog_comparator::DRIVER_NUM => f(Some(self.analog_comparator)),
            capsules_extra::nonvolatile_storage_driver::DRIVER_NUM => {
                f(Some(self.nonvolatile_storage))
            }
            capsules_extra::net::udp::DRIVER_NUM => f(Some(self.udp_driver)),
            kernel::ipc::DRIVER_NUM => f(Some(&self.ipc)),
            capsules_core::i2c_master_slave_driver::DRIVER_NUM => f(Some(self.i2c_master_slave)),
            capsules_core::spi_controller::DRIVER_NUM => f(Some(self.spi_controller)),
            kernel::process_load_utilities::DRIVER_NUM => f(Some(&self.process_loader)),
            _ => f(None),
        }
    }
}

/// This is in a separate, inline(never) function so that its stack frame is
/// removed when this function returns. Otherwise, the stack space used for
/// these static_inits is wasted.
#[inline(never)]
unsafe fn create_peripherals() -> &'static mut Nrf52840DefaultPeripherals<'static> {
    // Initialize chip peripheral drivers
    let nrf52840_peripherals = static_init!(
        Nrf52840DefaultPeripherals,
        Nrf52840DefaultPeripherals::new()
    );

    nrf52840_peripherals
}

impl <C: 'static + Chip> KernelResources<nrf52840::chip::NRF52<'static, Nrf52840DefaultPeripherals<'static>>>
    for Platform <C>
{
    type SyscallDriverLookup = Self;
    type SyscallFilter = ();
    type ProcessFault = ();
    type CredentialsCheckingPolicy = ();
    type Scheduler = RoundRobinSched<'static>;
    type SchedulerTimer = cortexm4::systick::SysTick;
    type WatchDog = ();
    type ContextSwitchCallback = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        &self
    }
    fn syscall_filter(&self) -> &Self::SyscallFilter {
        &()
    }
    fn process_fault(&self) -> &Self::ProcessFault {
        &()
    }
    fn credentials_checking_policy(&self) -> &'static Self::CredentialsCheckingPolicy {
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

/// Main function called after RAM initialized.
#[no_mangle]
pub unsafe fn main() {
    //--------------------------------------------------------------------------
    // INITIAL SETUP
    //--------------------------------------------------------------------------

    // Apply errata fixes and enable interrupts.
    nrf52840::init();

    // Set up peripheral drivers. Called in separate function to reduce stack
    // usage.
    let nrf52840_peripherals = create_peripherals();

    // Set up circular peripheral dependencies.
    nrf52840_peripherals.init();
    let base_peripherals = &nrf52840_peripherals.nrf52;

    // Configure kernel debug GPIOs as early as possible.
    kernel::debug::assign_gpios(
        Some(&nrf52840_peripherals.gpio_port[LED1_PIN]),
        Some(&nrf52840_peripherals.gpio_port[LED2_PIN]),
        Some(&nrf52840_peripherals.gpio_port[LED3_PIN]),
    );

    // Choose the channel for serial output. This board can be configured to use
    // either the Segger RTT channel or via UART with traditional TX/RX GPIO
    // pins.
    let uart_channel = if USB_DEBUGGING {
        // Initialize early so any panic beyond this point can use the RTT
        // memory object.
        let mut rtt_memory_refs = components::segger_rtt::SeggerRttMemoryComponent::new()
            .finalize(components::segger_rtt_memory_component_static!());

        // XXX: This is inherently unsafe as it aliases the mutable reference to
        // rtt_memory. This aliases reference is only used inside a panic
        // handler, which should be OK, but maybe we should use a const
        // reference to rtt_memory and leverage interior mutability instead.
        self::io::set_rtt_memory(&mut *rtt_memory_refs.get_rtt_memory_ptr());

        UartChannel::Rtt(rtt_memory_refs)
    } else {
        UartChannel::Pins(UartPins::new(UART_RTS, UART_TXD, UART_CTS, UART_RXD))
    };

    // Setup space to store the core kernel data structure.
    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(&PROCESSES));

    // Create (and save for panic debugging) a chip object to setup low-level
    // resources (e.g. MPU, systick).
    let chip = static_init!(
        nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>,
        nrf52840::chip::NRF52::new(nrf52840_peripherals)
    );
    CHIP = Some(chip);

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
    let process_management_capability =
        create_capability!(capabilities::ProcessManagementCapability);
    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);
    let memory_allocation_capability = create_capability!(capabilities::MemoryAllocationCapability);
    let gpio_port = &nrf52840_peripherals.gpio_port;

    //--------------------------------------------------------------------------
    // GPIO
    //--------------------------------------------------------------------------

    // Expose the D0-D13 Arduino GPIO pins to userspace.
    let gpio = components::gpio::GpioComponent::new(
        board_kernel,
        capsules_core::gpio::DRIVER_NUM,
        components::gpio_component_helper!(
            nrf52840::gpio::GPIOPin,
            0 => &nrf52840_peripherals.gpio_port[Pin::P1_01],
            1 => &nrf52840_peripherals.gpio_port[Pin::P1_02],
            2 => &nrf52840_peripherals.gpio_port[Pin::P1_03],
            3 => &nrf52840_peripherals.gpio_port[Pin::P1_04],
            4 => &nrf52840_peripherals.gpio_port[Pin::P1_05],
            5 => &nrf52840_peripherals.gpio_port[Pin::P1_06],
            6 => &nrf52840_peripherals.gpio_port[Pin::P1_07],
            7 => &nrf52840_peripherals.gpio_port[Pin::P1_08],
            8 => &nrf52840_peripherals.gpio_port[Pin::P1_10],
            9 => &nrf52840_peripherals.gpio_port[Pin::P1_11],
            10 => &nrf52840_peripherals.gpio_port[Pin::P1_12],
            11 => &nrf52840_peripherals.gpio_port[Pin::P1_13],
            12 => &nrf52840_peripherals.gpio_port[Pin::P1_14],
            13 => &nrf52840_peripherals.gpio_port[Pin::P1_15],
        ),
    )
    .finalize(components::gpio_component_static!(nrf52840::gpio::GPIOPin));

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

    // Tool for displaying information about processes.
    // let process_printer = components::process_printer::ProcessPrinterTextComponent::new()
    //     .finalize(components::process_printer_text_component_static!());
    // PROCESS_PRINTER = Some(process_printer);

    // Virtualize the UART channel for the console and for kernel debug.
    let uart_mux = components::console::UartMuxComponent::new(uart_channel, 115200)
        .finalize(components::uart_mux_component_static!());

    // Create the process console, an interactive terminal for managing
    // processes.
    // let pconsole = components::process_console::ProcessConsoleComponent::new(
    //     board_kernel,
    //     uart_mux,
    //     mux_alarm,
    //     process_printer,
    //     Some(reset),
    // )
    // .finalize(components::process_console_component_static!(
    //     nrf52840::rtc::Rtc<'static>
    // ));

    // Setup the serial console for userspace.
    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::console_component_static!());

    // Create the debugger object that handles calls to `debug!()`.
    components::debug_writer::DebugWriterComponent::new(uart_mux)
        .finalize(components::debug_writer_component_static!());


    //--------------------------------------------------------------------------
    // Process Loader (OTA)
    //--------------------------------------------------------------------------
    let process_loader = kernel::process::ProcessLoader::init(
        board_kernel,
        chip,
        &FAULT_RESPONSE,
        &memory_allocation_capability,
        PROCESSES.as_mut_ptr(),
        PROCESSES_REGION_START_ADDRESS.as_mut_ptr(),
        PROCESSES_REGION_SIZE.as_mut_ptr(),
        NUM_PROCS,
        &_sapps as *const u8 as usize,
        &_eapps as *const u8 as usize,
        &_eappmem as *const u8 as usize,
        &UNUSED_RAM_START_ADDR_INIT_VAL,
        &PROCESS_INDEX_INIT_VAL,
    );
    // power::configure_submodules(
    //     &peripherals.pa,
    //     &peripherals.pb,
    //     &peripherals.pc,
    //     power::SubmoduleConfig {
    //         rf233: true, 
    //         nrf52840: true,
    //         sensors: true,
    //         trng: true,
    //     },
    // );

    //--------------------------------------------------------------------------
    // AES
    //--------------------------------------------------------------------------

    let aes_mux = components::ieee802154::MuxAes128ccmComponent::new(&base_peripherals.ecb)
        .finalize(components::mux_aes128ccm_component_static!(
            nrf52840::aes::AesECB
        ));

    //--------------------------------------------------------------------------
    // BLE
    //--------------------------------------------------------------------------

    let ble_radio = components::ble::BLEComponent::new(
        board_kernel,
        capsules_extra::ble_advertising_driver::DRIVER_NUM,
        &base_peripherals.ble_radio,
        mux_alarm,
    )
    .finalize(components::ble_component_static!(
        nrf52840::rtc::Rtc,
        nrf52840::ble_radio::Radio
    ));

    //--------------------------------------------------------------------------
    // IEEE 802.15.4 and UDP
    //--------------------------------------------------------------------------

    let serial_num = nrf52840::ficr::FICR_INSTANCE.address();
    let serial_num_bottom_16 = serial_num[0] as u16 + ((serial_num[1] as u16) << 8);
    let src_mac_from_serial_num: MacAddress = MacAddress::Short(serial_num_bottom_16);
    let (ieee802154_radio, mux_mac) = components::ieee802154::Ieee802154Component::new(
        board_kernel,
        capsules_extra::ieee802154::DRIVER_NUM,
        &base_peripherals.ieee802154_radio,
        aes_mux,
        PAN_ID,
        serial_num_bottom_16,
    )
    .finalize(components::ieee802154_component_static!(
        nrf52840::ieee802154_radio::Radio,
        nrf52840::aes::AesECB<'static>
    ));

    let local_ip_ifaces = static_init!(
        [IPAddr; 3],
        [
            IPAddr([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ]),
            IPAddr([
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ]),
            IPAddr::generate_from_mac(capsules_extra::net::ieee802154::MacAddress::Short(
                serial_num_bottom_16
            )),
        ]
    );

    let (udp_send_mux, udp_recv_mux, udp_port_table) = components::udp_mux::UDPMuxComponent::new(
        mux_mac,
        DEFAULT_CTX_PREFIX_LEN,
        DEFAULT_CTX_PREFIX,
        DST_MAC_ADDR,
        src_mac_from_serial_num,
        local_ip_ifaces,
        mux_alarm,
    )
    .finalize(components::udp_mux_component_static!(nrf52840::rtc::Rtc));

    // UDP driver initialization happens here
    let udp_driver = components::udp_driver::UDPDriverComponent::new(
        board_kernel,
        capsules_extra::net::udp::driver::DRIVER_NUM,
        udp_send_mux,
        udp_recv_mux,
        udp_port_table,
        local_ip_ifaces,
    )
    .finalize(components::udp_driver_component_static!(nrf52840::rtc::Rtc));

    //--------------------------------------------------------------------------
    // TEMPERATURE (internal)
    //--------------------------------------------------------------------------

    let temp = components::temperature::TemperatureComponent::new(
        board_kernel,
        capsules_extra::temperature::DRIVER_NUM,
        &base_peripherals.temp,
    )
    .finalize(components::temperature_component_static!());

    //--------------------------------------------------------------------------
    // RANDOM NUMBER GENERATOR
    //--------------------------------------------------------------------------

    let rng = components::rng::RngComponent::new(
        board_kernel,
        capsules_core::rng::DRIVER_NUM,
        &base_peripherals.trng,
    )
    .finalize(components::rng_component_static!());

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
    // SPI
    //--------------------------------------------------------------------------

    let mux_spi = components::spi::SpiMuxComponent::new(&base_peripherals.spim0)
        .finalize(components::spi_mux_component_static!(nrf52840::spi::SPIM));

    // Create the SPI system call capsule.
    let spi_controller = components::spi::SpiSyscallComponent::new(
        board_kernel,
        mux_spi,
        &gpio_port[SPI_CS],
        capsules_core::spi_controller::DRIVER_NUM,
    )
    .finalize(components::spi_syscall_component_static!(
        nrf52840::spi::SPIM
    ));

    base_peripherals.spim0.configure(
        nrf52840::pinmux::Pinmux::new(SPI_MOSI as u32),
        nrf52840::pinmux::Pinmux::new(SPI_MISO as u32),
        nrf52840::pinmux::Pinmux::new(SPI_CLK as u32),
    );

    //--------------------------------------------------------------------------
    // ONBOARD EXTERNAL FLASH
    //--------------------------------------------------------------------------

    let mx25r6435f = components::mx25r6435f::Mx25r6435fComponent::new(
        Some(&gpio_port[SPI_MX25R6435F_WRITE_PROTECT_PIN]),
        Some(&gpio_port[SPI_MX25R6435F_HOLD_PIN]),
        &gpio_port[SPI_MX25R6435F_CHIP_SELECT] as &dyn kernel::hil::gpio::Pin,
        mux_alarm,
        mux_spi,
    )
    .finalize(components::mx25r6435f_component_static!(
        nrf52840::spi::SPIM,
        nrf52840::gpio::GPIOPin,
        nrf52840::rtc::Rtc
    ));

    // API for accessing nonvolatile storage for both the kernel and userspace.
    let nonvolatile_storage = components::nonvolatile_storage::NonvolatileStorageComponent::new(
        board_kernel,
        capsules_extra::nonvolatile_storage_driver::DRIVER_NUM,
        mx25r6435f,
        0x60000,   // Start address for userspace accessible region
        0x3FA0000, // Length of userspace accessible region
        0,         // Start address of kernel region
        0x60000,   // Length of kernel region
        NUM_PROCS,
        &PROCESSES_REGION_START_ADDRESS,
        &PROCESSES_REGION_SIZE,
    )
    .finalize(components::nonvolatile_storage_component_static!(
        capsules_extra::mx25r6435f::MX25R6435F<
            'static,
            capsules_core::virtualizers::virtual_spi::VirtualSpiMasterDevice<
                'static,
                nrf52840::spi::SPIM,
            >,
            nrf52840::gpio::GPIOPin,
            VirtualMuxAlarm<'static, nrf52840::rtc::Rtc>,
        >
    ));

    //--------------------------------------------------------------------------
    // I2C CONTROLLER/TARGET
    //--------------------------------------------------------------------------

    let i2c_master_slave = components::i2c::I2CMasterSlaveDriverComponent::new(
        board_kernel,
        capsules_core::i2c_master_slave_driver::DRIVER_NUM,
        &base_peripherals.twi1,
    )
    .finalize(components::i2c_master_slave_component_static!(
        nrf52840::i2c::TWI
    ));

    base_peripherals.twi1.configure(
        nrf52840::pinmux::Pinmux::new(I2C_SCL_PIN as u32),
        nrf52840::pinmux::Pinmux::new(I2C_SDA_PIN as u32),
    );
    base_peripherals.twi1.set_speed(nrf52840::i2c::Speed::K400);

    //--------------------------------------------------------------------------
    // ANALOG COMPARATOR
    //--------------------------------------------------------------------------

    // Initialize AC using AIN5 (P0.29) as VIN+ and VIN- as AIN0 (P0.02)
    // These are hardcoded pin assignments specified in the driver
    let analog_comparator = components::analog_comparator::AnalogComparatorComponent::new(
        &base_peripherals.acomp,
        components::analog_comparator_component_helper!(
            nrf52840::acomp::Channel,
            &nrf52840::acomp::CHANNEL_AC0
        ),
        board_kernel,
        capsules_extra::analog_comparator::DRIVER_NUM,
    )
    .finalize(components::analog_comparator_component_static!(
        nrf52840::acomp::Comparator
    ));

    //--------------------------------------------------------------------------
    // NRF CLOCK SETUP
    //--------------------------------------------------------------------------

    nrf52_components::NrfClockComponent::new(&base_peripherals.clock).finalize(());

    //--------------------------------------------------------------------------
    // TESTS
    //--------------------------------------------------------------------------

    // let alarm_test_component =
    //     components::test::multi_alarm_test::MultiAlarmTestComponent::new(&mux_alarm).finalize(
    //         components::multi_alarm_test_component_buf!(nrf52840::rtc::Rtc),
    //     );

    //--------------------------------------------------------------------------
    // USB EXAMPLES
    //--------------------------------------------------------------------------
    // Uncomment to experiment with this.

    // // Create the strings we include in the USB descriptor.
    // let strings = static_init!(
    //     [&str; 3],
    //     [
    //         "Nordic Semiconductor", // Manufacturer
    //         "nRF52840dk - TockOS",  // Product
    //         "serial0001",           // Serial number
    //     ]
    // );

    // CTAP Example
    //
    // let (ctap, _ctap_driver) = components::ctap::CtapComponent::new(
    //     board_kernel,
    //     capsules_extra::ctap::DRIVER_NUM,
    //     &nrf52840_peripherals.usbd,
    //     0x1915, // Nordic Semiconductor
    //     0x503a, // lowRISC generic FS USB
    //     strings,
    // )
    // .finalize(components::ctap_component_static!(nrf52840::usbd::Usbd));

    // ctap.enable();
    // ctap.attach();

    // Keyboard HID Example
    //
    // let (keyboard_hid, keyboard_hid_driver) = components::keyboard_hid::KeyboardHidComponent::new(
    //     board_kernel,
    //     capsules_core::driver::KeyboardHid,
    //     &nrf52840_peripherals.usbd,
    //     0x1915, // Nordic Semiconductor
    //     0x503a,
    //     strings,
    // )
    // .finalize(components::keyboard_hid_component_static!(
    //     nrf52840::usbd::Usbd
    // ));

    // keyboard_hid.enable();
    // keyboard_hid.attach();

    //--------------------------------------------------------------------------
    // PLATFORM SETUP, SCHEDULER, AND START KERNEL LOOP
    //--------------------------------------------------------------------------

    let scheduler = components::sched::round_robin::RoundRobinComponent::new(&PROCESSES)
        .finalize(components::round_robin_component_static!(NUM_PROCS));

    let platform = Platform {
        button,
        ble_radio,
        ieee802154_radio,
        // pconsole,
        console,
        led,
        gpio,
        rng,
        adc,
        temp,
        alarm,
        analog_comparator,
        nonvolatile_storage,
        process_loader,
        udp_driver,
        ipc: kernel::ipc::IPC::new(
            board_kernel,
            kernel::ipc::DRIVER_NUM,
            &memory_allocation_capability,
        ),
        i2c_master_slave,
        spi_controller,
        scheduler,
        systick: cortexm4::systick::SysTick::new_with_calibration(64000000),
    };

    // let _ = platform.pconsole.start();
    base_peripherals.adc.calibrate();

    // test::aes_test::run_aes128_ctr(&base_peripherals.ecb);
    // test::aes_test::run_aes128_cbc(&base_peripherals.ecb);
    // test::aes_test::run_aes128_ecb(&base_peripherals.ecb);

    debug!("Initialization complete. Entering main loop\r");
    debug!("{}", &nrf52840::ficr::FICR_INSTANCE);

    // alarm_test_component.run();

    // These symbols are defined in the linker script.
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

    let res = kernel::process::load_processes(
        board_kernel,
        chip,
        core::slice::from_raw_parts(
            &_sapps as *const u8,
            &_eapps as *const u8 as usize - &_sapps as *const u8 as usize,
        ),
        core::slice::from_raw_parts_mut(
            &mut _sappmem as *mut u8,
            &_eappmem as *const u8 as usize - &_sappmem as *const u8 as usize,
        ),
        &mut PROCESSES,
        &FAULT_RESPONSE,
        &process_management_capability,
        &mut PROCESSES_REGION_START_ADDRESS,
        &mut PROCESSES_REGION_SIZE,
    );  // )
    // .unwrap_or_else(|err| {
    //     debug!("Error loading processes!");
    //     debug!("{:?}", err);
    // });
    match res{
        Ok((remaining_memory, index)) => {
            UNUSED_RAM_START_ADDR_INIT_VAL = remaining_memory;
            PROCESS_INDEX_INIT_VAL = index;
        }
        Err(e) => debug!("Error loading processes!: {:?}", e)
    }

    board_kernel.kernel_loop(&platform, chip, Some(&platform.ipc), &main_loop_capability);
}
