Arduino Nano RP2040 Connect
===========================

<img src="https://store-usa.arduino.cc/cdn/shop/products/ABX00052_01.iso_1000x750.jpg?v=1629816097" width="35%">

The [Arduino Nano RP2040 Connect](https://docs.arduino.cc/hardware/nano-rp2040-connect) is an Arduino Nano
board built using the Raspberry Pi Foundation's RP2040 chip.

## Getting Started

First, follow the [Tock Getting Started guide](../../doc/Getting_Started.md)

## Installing elf2uf2-rs

The Nano RP2040 uses UF2 files for flashing. Tock compiles to an ELF file.
The `elf2uf2-rs` utility is needed to transform the Tock ELF file into an UF2 file.

To install `elf2uf2`, run the commands:

```bash
$ cargo install elf2uf2-rs
```

## Flashing the kernel

The Arduino Nano RP2040 Connect can be programmed using its bootloader, which requires an UF2 file.

### Enter BOOTSEL mode

To flash the Nano RP2040, it needs to be put into BOOTSEL mode. This will mount
a flash drive that allows one to copy a UF2 file. While the official
documentation states that double pressing the on-board button enter this mode,
this seems to work only while running Arduino's original software.

If double tapping the button does not enter BOOTSEL mode (the flash drive is not mounted),
the device can be [forced into BOOTSEL mode using a jumper wire](https://docs.arduino.cc/tutorials/nano-rp2040-connect/rp2040-01-technical-reference#forcing-bootloader).

1. Disconnect the board from USB
2. Connect the GND pin with the REC pin
3. Connect the board to USB
4. Wait for the flash drive to mount
5. Disconnect the board from USB (*very important*)

`cd` into `boards/nano_rp2040_connect` directory and run:

```bash
$ make flash

(or)

$ make flash-debug
```

> Note: The Makefile provides the BOOTSEL_FOLDER variable that points towards the mount point of
> the Nano RP2040 flash drive. By default, this is located in `/media/$(USER)/RP2040`. This might
> be different on several systems, make sure to adjust it.

## Flashing app

Enter BOOTSEL mode.

Apps are built out-of-tree. Once an app is built, you can add the path to it in the Makefile (APP variable), then run:
```bash
$ APP="<path to app's tbf file>" make flash-app
```

## Serial Interface

Tock for Nano RP2040 does not yet support USB. The serial console is using UART0, 
meaning that a [USB TTL adapter](https://www.adafruit.com/product/954) is needed to interface the board.
