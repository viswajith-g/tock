// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Tock kernel for the Nordic Semiconductor nRF52840 development kit (DK).

#![no_std]
#![no_main]
#![deny(missing_docs)]

use core::ptr::addr_of;

use kernel::component::Component;
use kernel::deferred_call::DeferredCallClient;
use kernel::hil::led::LedLow;
use kernel::hil::time::Counter;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::process::ProcessArray;
use kernel::process::ProcessLoadingAsync;
use kernel::scheduler::round_robin::RoundRobinSched;
use kernel::{capabilities, create_capability, static_init};
use nrf52840::gpio::Pin;
use nrf52840::interrupt_service::Nrf52840DefaultPeripherals;
use nrf52_components::{UartChannel, UartPins};
// use kernel::process::ShortId;

mod app_id_assigner_name_metadata;
// mod checker_credentials_not_required;

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

// /// I2C pins
// const I2C_SDA_PIN: Pin = Pin::P0_26;
// const I2C_SCL_PIN: Pin = Pin::P0_27;

/// Debug Writer
pub mod io;

// State for loading and holding applications.
// How should the kernel respond when a process faults.
const FAULT_RESPONSE: capsules_system::process_policies::PanicFaultPolicy =
    capsules_system::process_policies::PanicFaultPolicy {};

// Number of concurrent processes this platform supports.
const NUM_PROCS: usize = 8;

/// Static variables used by io.rs.
static mut PROCESSES: Option<&'static ProcessArray<NUM_PROCS>> = None;
static mut CHIP: Option<&'static nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>> = None;
// Static reference to process printer for panic dumps.
// static mut PROCESS_PRINTER: Option<&'static capsules_system::process_printer::ProcessPrinterText> =
//     None;

// How many credential verifying keys the kernel supports.
const NUM_CREDENTIAL_KEYS: usize = 1;
// Length of the key used for the ECDSA-P256 signature.
const SIGNATURE_KEY_LEN: usize = 64;
// Length of the hash used for the signature (SHA-256).
const SIGNATURE_HASH_LEN: usize = 32;
// Length of the ECDSA-P256 signature.
const SIGNATURE_SIG_LEN: usize = 64;

kernel::stack_size! {0x2000}

//------------------------------------------------------------------------------
// SYSCALL DRIVER TYPE DEFINITIONS
//------------------------------------------------------------------------------

type AlarmDriver = components::alarm::AlarmDriverComponentType<nrf52840::rtc::Rtc<'static>>;
type TemperatureDriver =
    components::temperature::TemperatureComponentType<nrf52840::temperature::Temp<'static>>;
type RngDriver = components::rng::RngComponentType<nrf52840::trng::Trng<'static>>;

// type FlashUser =
//     capsules_core::virtualizers::virtual_flash::FlashUser<'static, nrf52840::nvmc::Nvmc>;
// type NonVolatilePages = components::dynamic_binary_storage::NVPages<FlashUser>;

// type DynamicBinaryStorage<'a> = kernel::dynamic_binary_storage::SequentialDynamicBinaryStorage<
//     'static,
//     'static,
//     nrf52840::chip::NRF52<'a, Nrf52840DefaultPeripherals<'a>>,
//     // kernel::process::ProcessStandardDebugNone,
//     (),
//     NonVolatilePages,
// >;
type Ieee802154RawDriver =
    components::ieee802154::Ieee802154RawComponentType<nrf52840::ieee802154_radio::Radio<'static>>;
// pub type Ieee802154Driver = components::ieee802154::Ieee802154ComponentType<
//     nrf52840::ieee802154_radio::Radio<'static>,
//     nrf52840::aes::AesECB<'static>,
// >;

/// Userspace EUI64 driver.
type Eui64Driver = components::eui64::Eui64ComponentType;

// fn create_short_id_from_name(name: &str, metadata: u8) -> kernel::process::ShortId {
//     let sum = kernel::utilities::helpers::crc32_posix(name.as_bytes());
//     let sid = ((metadata as u32) << 28) | (sum & 0xFFFFFFF);
//     core::num::NonZeroU32::new(sid).into()
// }

type Verifier = ecdsa_sw::p256_verifier::EcdsaP256SignatureVerifier<'static>;
type SignatureVerifyInMemoryKeys =
    components::signature_verify_in_memory_keys::SignatureVerifyInMemoryKeysComponentType<
        Verifier,
        NUM_CREDENTIAL_KEYS,
        SIGNATURE_KEY_LEN,
        SIGNATURE_HASH_LEN,
        SIGNATURE_SIG_LEN,
    >;
// type SignatureChecker = components::appid::checker_signature::AppCheckerSignatureComponentType<
//     SignatureVerifyInMemoryKeys,
//     capsules_extra::sha256::Sha256Software<'static>,
//     SIGNATURE_HASH_LEN,
//     SIGNATURE_SIG_LEN,
// >;

// //------------------------------------------------------------------------------
// // SHORTID HELPER FUNCTION
// //------------------------------------------------------------------------------

// fn create_short_id_from_name(name: &str, metadata: u8) -> ShortId {
//     let sum = kernel::utilities::helpers::crc32_posix(name.as_bytes());

//     // Combine the metadata and CRC into the short id.
//     let sid = ((metadata as u32) << 28) | (sum & 0xFFFFFFF);

//     core::num::NonZeroU32::new(sid).into()
// }

/// Supported drivers by the platform
pub struct Platform {
    console: &'static capsules_core::console::Console<'static>,
    button: &'static capsules_core::button::Button<'static, nrf52840::gpio::GPIOPin<'static>>,
    led: &'static capsules_core::led::LedDriver<
        'static,
        kernel::hil::led::LedLow<'static, nrf52840::gpio::GPIOPin<'static>>,
        4,
    >,
    temp: &'static TemperatureDriver,
    ipc: kernel::ipc::IPC<{ NUM_PROCS as u8 }>,
    rng: &'static RngDriver,
    alarm: &'static AlarmDriver,
    scheduler: &'static RoundRobinSched<'static>,
    systick: cortexm4::systick::SysTick,
    processes: &'static ProcessArray<NUM_PROCS>,
    // ambient_light: &'static capsules_extra::ambient_light::AmbientLight<'static>,
    // dynamic_app_loader: &'static capsules_extra::app_loader::AppLoader<
    //     DynamicBinaryStorage<'static>,
    //     DynamicBinaryStorage<'static>,
    // >,
    nonvolatile_storage:
        &'static capsules_extra::isolated_nonvolatile_storage_driver::IsolatedNonvolatileStorage<
            'static,
            {
                components::isolated_nonvolatile_storage::ISOLATED_NONVOLATILE_STORAGE_APP_REGION_SIZE_DEFAULT
            },
        >,
    ieee802154: &'static Ieee802154RawDriver,
    eui64: &'static Eui64Driver,
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
            capsules_extra::temperature::DRIVER_NUM => f(Some(self.temp)),
            capsules_core::rng::DRIVER_NUM => f(Some(self.rng)),
            capsules_core::button::DRIVER_NUM => f(Some(self.button)),
            capsules_extra::eui64::DRIVER_NUM => f(Some(self.eui64)),
            capsules_extra::ieee802154::DRIVER_NUM => f(Some(self.ieee802154)),
            // capsules_extra::ambient_light::DRIVER_NUM => f(Some(self.ambient_light)),
            kernel::ipc::DRIVER_NUM => f(Some(&self.ipc)),
            capsules_extra::isolated_nonvolatile_storage_driver::DRIVER_NUM => {
                f(Some(self.nonvolatile_storage))
            }
            // capsules_extra::app_loader::DRIVER_NUM => f(Some(self.dynamic_app_loader)),
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
    type Scheduler = RoundRobinSched<'static>;
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
    fn process_loaded(&self, _result: Result<(), kernel::process::ProcessLoadError>) {
        unsafe {
            // set P0.27 as output
            core::ptr::write_volatile(GPIO_DIRSET as *mut u32, 1 << 26);
            // set P0.27 HIGH
            core::ptr::write_volatile(GPIO_OUTCLR as *mut u32, 1 << 26);
        }
    }

    fn process_loading_finished(&self) {
        // kernel::debug!("Processes Loaded at Main:");

        // for (i, proc) in self.processes.as_slice().iter().enumerate() {
        //     proc.get().map(|p| {
        //         kernel::debug!("[{}] {}", i, p.get_process_name());
        //         kernel::debug!("    ShortId: {}", p.short_app_id());
        //     });
        // }
    }
}

const GPIO_P0_BASE: u32 = 0x5000_0000;
const GPIO_DIRSET: u32 = GPIO_P0_BASE + 0x518;  // set direction to output
const GPIO_OUTSET: u32 = GPIO_P0_BASE + 0x508;  // set pin HIGH
const GPIO_OUTCLR: u32 = GPIO_P0_BASE + 0x50C;  // set pin LOW

/// Main function called after RAM initialized.
#[no_mangle]
pub unsafe fn main() {
    //--------------------------------------------------------------------------
    // INITIAL SETUP
    //--------------------------------------------------------------------------
    // set P0.27 as output
    core::ptr::write_volatile(GPIO_DIRSET as *mut u32, 1 << 26);
    // set P0.27 HIGH
    core::ptr::write_volatile(GPIO_OUTCLR as *mut u32, 1 << 26);
    nrf52840::init();

    let nrf52840_peripherals = create_peripherals();

    nrf52840_peripherals.init();
    let base_peripherals = &nrf52840_peripherals.nrf52;

    let uart_channel = UartChannel::Pins(UartPins::new(UART_RTS, UART_TXD, UART_CTS, UART_RXD));

    let processes = components::process_array::ProcessArrayComponent::new()
        .finalize(components::process_array_component_static!(NUM_PROCS));
    PROCESSES = Some(processes);

    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(processes.as_slice()));

    let chip = static_init!(
        nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>,
        nrf52840::chip::NRF52::new(nrf52840_peripherals)
    );
    CHIP = Some(chip);

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

    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);
    let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

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

    let uart_mux = components::console::UartMuxComponent::new(uart_channel, 115200)
        .finalize(components::uart_mux_component_static!());

    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::console_component_static!());

    // let process_printer = components::process_printer::ProcessPrinterTextComponent::new()
    //     .finalize(components::process_printer_text_component_static!());
    // PROCESS_PRINTER = Some(process_printer);

    // let pconsole = components::process_console::ProcessConsoleComponent::new(
    //     board_kernel,
    //     uart_mux,
    //     mux_alarm,
    //     process_printer,
    //     Some(cortexm4::support::reset),
    // )
    // .finalize(components::process_console_component_static!(
    //     nrf52840::rtc::Rtc<'static>
    // ));

    // components::debug_writer::DebugWriterComponent::new::<
    //     <ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider,
    // >(
    //     uart_mux,
    //     create_capability!(capabilities::SetDebugWriterCapability),
    // )
    // .finalize(components::debug_writer_component_static!());

    //--------------------------------------------------------------------------
    // RNG
    //--------------------------------------------------------------------------

    let rng = components::rng::RngComponent::new(
        board_kernel,
        capsules_core::rng::DRIVER_NUM,
        &base_peripherals.trng,
    )
    .finalize(components::rng_component_static!(nrf52840::trng::Trng));

    //--------------------------------------------------------------------------
    // VIRTUAL FLASH
    //--------------------------------------------------------------------------

    // let mux_flash = components::flash::FlashMuxComponent::new(&nrf52840_peripherals.nrf52.nvmc)
    //     .finalize(components::flash_mux_component_static!(
    //         nrf52840::nvmc::Nvmc
    //     ));

    // let virtual_flash_dbs = components::flash::FlashUserComponent::new(mux_flash).finalize(
    //     components::flash_user_component_static!(nrf52840::nvmc::Nvmc),
    // );

    //--------------------------------------------------------------------------
    // TEMPERATURE
    //--------------------------------------------------------------------------

    let temp = components::temperature::TemperatureComponent::new(
        board_kernel,
        capsules_extra::temperature::DRIVER_NUM,
        &base_peripherals.temp,
    )
    .finalize(components::temperature_component_static!(
        nrf52840::temperature::Temp
    ));

    // //--------------------------------------------------------------------------
    // // I2C
    // //--------------------------------------------------------------------------
    // let mux_i2c = components::i2c::I2CMuxComponent::new(&base_peripherals.twi1, None)
    //     .finalize(components::i2c_mux_component_static!(nrf52840::i2c::TWI));
    // base_peripherals.twi1.configure(
    //     nrf52840::pinmux::Pinmux::new(I2C_SCL_PIN as u32),
    //     nrf52840::pinmux::Pinmux::new(I2C_SDA_PIN as u32),
    // );

    // //--------------------------------------------------------------------------
    // // ISL29035 AMBIENT LIGHT SENSOR
    // //--------------------------------------------------------------------------

    // let isl29035 = components::isl29035::Isl29035Component::new(mux_i2c, mux_alarm)
    //     .finalize(components::isl29035_component_static!(
    //         nrf52840::rtc::Rtc,
    //         nrf52840::i2c::TWI
    //     ));

    // let ambient_light = components::isl29035::AmbientLightComponent::new(
    //     board_kernel,
    //     capsules_extra::ambient_light::DRIVER_NUM,
    //     isl29035,
    // )
    // .finalize(components::ambient_light_component_static!());

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
    // NRF CLOCK SETUP
    //--------------------------------------------------------------------------

    nrf52_components::NrfClockComponent::new(&base_peripherals.clock).finalize(());

    //--------------------------------------------------------------------------
    // RAW 802.15.4
    //--------------------------------------------------------------------------

    let device_id = (*addr_of!(nrf52840::ficr::FICR_INSTANCE)).id();

    let eui64 = components::eui64::Eui64Component::new(u64::from_le_bytes(device_id))
        .finalize(components::eui64_component_static!());
        

    let ieee802154 = components::ieee802154::Ieee802154RawComponent::new(
        board_kernel,
        capsules_extra::ieee802154::DRIVER_NUM,
        &nrf52840_peripherals.ieee802154_radio,
    )
    .finalize(components::ieee802154_raw_component_static!(
        nrf52840::ieee802154_radio::Radio,
    ));

    //------------------------------------------------------------------------
    // NONVOLATILE STORAGE
    //--------------------------------------------------------------------------

    // 4kB of userspace-accessible storage, page aligned:
    // kernel::storage_volume!(APP_STORAGE, 8);

    // let nonvolatile_storage = components::isolated_nonvolatile_storage::IsolatedNonvolatileStorageComponent::new(
    //     board_kernel,
    //     capsules_extra::isolated_nonvolatile_storage_driver::DRIVER_NUM,
    //     &nrf52840_peripherals.nrf52.nvmc,
    //     core::ptr::addr_of!(APP_STORAGE) as usize,
    //     APP_STORAGE.len()
    // )
    // .finalize(components::isolated_nonvolatile_storage_component_static!(
    //     nrf52840::nvmc::Nvmc,
    //     { components::isolated_nonvolatile_storage::ISOLATED_NONVOLATILE_STORAGE_APP_REGION_SIZE_DEFAULT }
    // ));

    const APP_STORAGE_ADDR: usize = 0x90000; 
    const APP_STORAGE_SIZE: usize = 8 * 1024;
    
    let nonvolatile_storage = components::isolated_nonvolatile_storage::IsolatedNonvolatileStorageComponent::new(
        board_kernel,
        capsules_extra::isolated_nonvolatile_storage_driver::DRIVER_NUM,
        &nrf52840_peripherals.nrf52.nvmc,
        APP_STORAGE_ADDR,
        APP_STORAGE_SIZE,
    )
    .finalize(components::isolated_nonvolatile_storage_component_static!(
        nrf52840::nvmc::Nvmc,
        { components::isolated_nonvolatile_storage::ISOLATED_NONVOLATILE_STORAGE_APP_REGION_SIZE_DEFAULT }
    ));

    // //--------------------------------------------------------------------------
    // // CREDENTIAL CHECKING
    // //--------------------------------------------------------------------------

    // let checking_policy = components::appid::checker_null::AppCheckerNullComponent::new()
    //     .finalize(components::app_checker_null_component_static!());

    // // let assigner = components::appid::assigner_tbf::AppIdAssignerTbfHeaderComponent::new()
    // //     .finalize(components::appid_assigner_tbf_header_component_static!());
    // let assigner = components::appid::assigner_name::AppIdAssignerNamesComponent::new()
    // .finalize(components::appid_assigner_names_component_static!());

    // let checker = components::appid::checker::ProcessCheckerMachineComponent::new(checking_policy)
    //     .finalize(components::process_checker_machine_component_static!());

    //--------------------------------------------------------------------------
    // CREDENTIAL CHECKING
    //--------------------------------------------------------------------------

    // Create the software-based SHA engine.
    let sha = components::sha::ShaSoftware256Component::new()
        .finalize(components::sha_software_256_component_static!());

    // Create the credential checker.
    //
    // Setup an example key.
    //
    // - `ec-secp256r1-priv-key.pem`:
    //   ```
    //   -----BEGIN EC PRIVATE KEY-----
    //   MHcCAQEEIGU0zCXHLqxDmrHHAWEQP5zNfWRQrAiIpH9YwxHlqysmoAoGCCqGSM49
    //   AwEHoUQDQgAE4BM6kKdKNWFRjuFECfFpwc9q239+Uvi3QXniTVdBI1IuthIDs4UQ
    //   5fMlB2KPVJWCV0VQvaPiF+g0MIkmTCNisQ==
    //   -----END EC PRIVATE KEY-----
    //   ```
    //
    // - `ec-secp256r1-pub-key.pem`:
    //   ```
    //   -----BEGIN PUBLIC KEY-----
    //   MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4BM6kKdKNWFRjuFECfFpwc9q239+
    //   Uvi3QXniTVdBI1IuthIDs4UQ5fMlB2KPVJWCV0VQvaPiF+g0MIkmTCNisQ==
    //   -----END PUBLIC KEY-----
    //   ```
    //
    // You can add the correct signature to a TBF by saving the private key to
    // a file and then running:
    //
    //     tockloader tbf credential add ecdsap256 --private-key ec-secp256r1-priv-key.pem
    //
    let verifying_key0 = kernel::static_init!(
        [u8; SIGNATURE_KEY_LEN],
        [
            0xe0, 0x13, 0x3a, 0x90, 0xa7, 0x4a, 0x35, 0x61, 0x51, 0x8e, 0xe1, 0x44, 0x09, 0xf1,
            0x69, 0xc1, 0xcf, 0x6a, 0xdb, 0x7f, 0x7e, 0x52, 0xf8, 0xb7, 0x41, 0x79, 0xe2, 0x4d,
            0x57, 0x41, 0x23, 0x52, 0x2e, 0xb6, 0x12, 0x03, 0xb3, 0x85, 0x10, 0xe5, 0xf3, 0x25,
            0x07, 0x62, 0x8f, 0x54, 0x95, 0x82, 0x57, 0x45, 0x50, 0xbd, 0xa3, 0xe2, 0x17, 0xe8,
            0x34, 0x30, 0x89, 0x26, 0x4c, 0x23, 0x62, 0xb1
        ]
    );
    let verifying_keys = kernel::static_init!(
        [&'static mut [u8; SIGNATURE_KEY_LEN]; NUM_CREDENTIAL_KEYS],
        [verifying_key0]
    );
    // Setup the ECDSA-P256 verifier.
    let ecdsa_p256_verifying_key =
        kernel::static_init!([u8; SIGNATURE_KEY_LEN], [0; SIGNATURE_KEY_LEN]);
    let ecdsa_p256_verifier = kernel::static_init!(
        ecdsa_sw::p256_verifier::EcdsaP256SignatureVerifier<'static>,
        ecdsa_sw::p256_verifier::EcdsaP256SignatureVerifier::new(ecdsa_p256_verifying_key)
    );
    ecdsa_p256_verifier.register();

    // Setup the in-memory key selector.
    let verifier_multiple_keys =
        components::signature_verify_in_memory_keys::SignatureVerifyInMemoryKeysComponent::new(
            ecdsa_p256_verifier,
            verifying_keys,
        )
        .finalize(
            components::signature_verify_in_memory_keys_component_static!(
                Verifier,
                NUM_CREDENTIAL_KEYS,
                SIGNATURE_KEY_LEN,
                SIGNATURE_HASH_LEN,
                SIGNATURE_SIG_LEN,
            ),
        );

    // Policy checks for a valid EcdsaNistP256 signature.
    let checking_policy_signature =
        components::appid::checker_signature::AppCheckerSignatureComponent::new(
            sha,
            verifier_multiple_keys,
            tock_tbf::types::TbfFooterV2CredentialsType::EcdsaNistP256,
        )
        .finalize(components::app_checker_signature_component_static!(
            SignatureVerifyInMemoryKeys,
            capsules_extra::sha256::Sha256Software<'static>,
            SIGNATURE_HASH_LEN,
            SIGNATURE_SIG_LEN,
        ));

    // // Wrap the policy checker with a custom version that does not require valid
    // // credentials to load the app. We are ok with this for this tutorial
    // // because the verifying key (or lack thereof) is encoded in the AppId so
    // // we can still check if an app is signed or not.
    // let checking_policy = static_init!(
    //     checker_credentials_not_required::AppCheckerCredentialsNotRequired<
    //         SignatureChecker,
    //     >,
    //     checker_credentials_not_required::AppCheckerCredentialsNotRequired::new(
    //         checking_policy_signature
    //     ),
    // );

    // Create the AppID assigner.
    let assigner = static_init!(
        app_id_assigner_name_metadata::AppIdAssignerNameMetadata,
        app_id_assigner_name_metadata::AppIdAssignerNameMetadata::new()
    );

    // Create the process checking machine.
    let checker = components::appid::checker::ProcessCheckerMachineComponent::new(checking_policy_signature)
        .finalize(components::process_checker_machine_component_static!());

    //--------------------------------------------------------------------------
    // STORAGE PERMISSIONS
    //--------------------------------------------------------------------------

    let storage_permissions_policy =
        components::storage_permissions::individual::StoragePermissionsIndividualComponent::new()
            .finalize(
                components::storage_permissions_individual_component_static!(
                    nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>,
                    // kernel::process::ProcessStandardDebugFull,
                    ()
                ),
            );

    //--------------------------------------------------------------------------
    // PROCESS LOADING
    //--------------------------------------------------------------------------

    // extern "C" {
    //     /// Beginning of the RAM region for app memory.
    //     static mut _sappmem: u8;
    //     /// End of the RAM region for app memory.
    //     static _eappmem: u8;
    // }

    // const FLASH_START: usize = 0x000000;
    // const FLASH_END: usize = 0x100000;

    // let app_flash = core::slice::from_raw_parts(
    //     FLASH_START as *const u8,
    //     FLASH_END - FLASH_START,
    // );

    // let app_memory = core::slice::from_raw_parts_mut(
    //     core::ptr::addr_of_mut!(_sappmem),
    //     core::ptr::addr_of!(_eappmem) as usize - core::ptr::addr_of!(_sappmem) as usize,
    // );

    extern "C" {
        static _sapps: u8;
        static _eapps: u8;
        static mut _sappmem: u8;
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
        // kernel::process::ProcessStandardDebugFull,
        (),
        NUM_PROCS
    ));

    //--------------------------------------------------------------------------
    // DYNAMIC APP LOADING
    //--------------------------------------------------------------------------

    // let dynamic_binary_storage =
    //     components::dynamic_binary_storage::SequentialBinaryStorageComponent::new(
    //         virtual_flash_dbs,
    //         loader,
    //     )
    //     .finalize(components::sequential_binary_storage_component_static!(
    //         FlashUser,
    //         nrf52840::chip::NRF52<Nrf52840DefaultPeripherals>,
    //         // kernel::process::ProcessStandardDebugFull,
    //         (),
    //     ));

    // let dynamic_app_loader = components::app_loader::AppLoaderComponent::new(
    //     board_kernel,
    //     capsules_extra::app_loader::DRIVER_NUM,
    //     dynamic_binary_storage,
    //     dynamic_binary_storage,
    // )
    // .finalize(components::app_loader_component_static!(
    //     DynamicBinaryStorage<'static>,
    //     DynamicBinaryStorage<'static>,
    // ));

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
            led,
            temp,
            ipc: kernel::ipc::IPC::new(
                board_kernel,
                kernel::ipc::DRIVER_NUM,
                &grant_cap,
            ),
            rng,
            alarm,
            scheduler,
            systick: cortexm4::systick::SysTick::new_with_calibration(64000000),
            processes,
            // ambient_light,
            // dynamic_app_loader,
            eui64,
            ieee802154,
            nonvolatile_storage,
        }
    );
    loader.set_client(platform);

    core::ptr::write_volatile(GPIO_DIRSET as *mut u32, 1 << 26);
    // set P0.27 HIGH
    core::ptr::write_volatile(GPIO_OUTSET as *mut u32, 1 << 26);

    // let _ = pconsole.start();

    board_kernel.kernel_loop(
        platform,
        chip,
        Some(&platform.ipc),
        &main_loop_capability,
    );
}
