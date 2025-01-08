i.MX RT1050 Crossover MCU with Arm® Cortex®-M7 core
====================================================

For more details about the board [visit the NXP  board website](https://www.nxp.com/design/development-boards/i-mx-evaluation-and-development-boards/i-mx-rt1050-evaluation-kit:MIMXRT1050-EVK). Details about the chip can be found [here](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1050-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1050).


## Flashing the kernel

Prerequisites:
- NXP MCUXpresso SDK software

  The `crt_emu_cm_redlink` binary for flashing the board is not added
  to the PATH in a standard MCUXpresso installation. Due to the
  version- and OS-dependent paths, this has to be done manually. It
  will be located in paths such as

  - on macOS: `/Applications/MCUXpressoIDE_11.1.1_3241/ide/plugins/com.nxp.mcuxpresso.tools.bin.macosx_11.1.0.202002241259/binaries/`
  - on Debian-based Linux distributions: `/usr/local/mcuxpressoide-11.1.1_3241/ide/plugins/com.nxp.mcuxpresso.tools.bin.linux_10.3.1.201811211038/binaries/`

  Please add these directories to your path, like so:
  ```bash
  export PATH=$PATH:<the directory containing crt_emu_cm_redlink>`
  ```
- for the `flash-app` target: `gcc-arm-none-eabi`

To compile Tock and flash the kernel onto the board, run `make
flash`. Its output should look something like:

```bash
$ make flash
    Finished release [optimized + debuginfo] target(s) in 0.02s
   text	   data	    bss	    dec	    hex	filename
  82365	      0	  16384	  98749	  181bd	/home/USER/tock/target/thumbv7em-none-eabi/release/imxrt1050-evkb
crt_emu_cm_redlink \
	--flash-load-exec "/home/USER/tock/target/thumbv7em-none-eabi/release/imxrt1050-evkb.elf" \
	-p MIMXRT1052xxxxB --ConnectScript RT1050_connect.scp \
	--flash-driver= -x . --flash-dir /Flash --flash-hashing
Ns: MCUXpresso IDE RedlinkMulti Driver v11.3 (Mar 30 2021 17:55:57 - crt_emu_cm_redlink build 18)
Wc(03). No cache support.
Nc: Found chip XML file in ./MIMXRT1052xxxxB.xml
Nc: Restarted LinkServer process (PID 22344).
```

## Running an app

Apps are built out-of-tree. Once an app is built, you can use
`arm-none-eabi-objcopy` with `--update-section` to create an ELF image
with your app(s) included.

```bash
$ arm-none-eabi-objcopy  \
    --set-section-flags .apps=LOAD,ALLOC \
    target/thumbv7em-none-eabi/debug/imxrt1050-evkb.elf \
    target/thumbv7em-none-eabi/debug/imxrt1050-evkb-app.axf
arm-none-eabi-objcopy  \
    --update-section .apps=../../../libtock-c/examples/c_hello/build/cortex-m7/cortex-m7.tbf \
    target/thumbv7em-none-eabi/debug/imxrt1050-evkb-app.axf
```

Conveniently, the Makefile also offers a target which will integrate
the `tbf` app bundle into the ELF image prior to flashing it to the
board:

```bash
$ make flash-app APP=../../../libtock-c/examples/c_hello/build/cortex-m7/cortex-m7.tbf
```

## Advanced debugging

If you want to run a program step by step, set breakpoints or other advanced debugging features,
you can follow the steps below:

First step: Import a Hello World example project from the SDK and build the project. This way you will have the following file hierarchy in the Project Explorer Tab:

![image info](./pictures/project-explorer.png)

Second step: Copy the app image from target/thumbv7em-none-eabi/debug/imxrt1050-evkb-app.axf to the Debug folder in MCU Expresso (via drag and drop):

![image info](./pictures/copy-to-debug.png)

Next, flash the example program once in order to generate the LinkServer Debug file, like this:

![image info](./pictures/flash-example.png)

Next step, modify the LinkServer Debug, like this:

- From Search Project, select the imxrt1050-evkb-app.axf file you copied earlier
- Check the "Disable auto build" option
- Press Apply and Continue

![image info](./pictures/config-link-server.png)

Finally, press debug to run the code on the board and enjoy!
