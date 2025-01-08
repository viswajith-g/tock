// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Test the AES hardware.

use capsules_core::test::capsule_test::{CapsuleTest, CapsuleTestClient};
use core::cell::Cell;
use kernel::debug;
use kernel::hil;
use kernel::hil::symmetric_encryption::{
    AES128Ctr, AES128, AES128CBC, AES128ECB, AES128_BLOCK_SIZE, AES128_KEY_SIZE,
};
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::cells::TakeCell;

pub struct TestAes128Ctr<'a, A: 'a> {
    aes: &'a A,

    key: TakeCell<'a, [u8]>,
    iv: TakeCell<'a, [u8]>,
    source: TakeCell<'static, [u8]>,
    data: TakeCell<'static, [u8]>,
    test_decrypt: bool,

    encrypting: Cell<bool>,
    use_source: Cell<bool>,

    client: OptionalCell<&'static dyn CapsuleTestClient>,
}

pub struct TestAes128Cbc<'a, A: 'a> {
    aes: &'a A,

    key: TakeCell<'a, [u8]>,
    iv: TakeCell<'a, [u8]>,
    source: TakeCell<'static, [u8]>,
    data: TakeCell<'static, [u8]>,
    test_decrypt: bool,

    encrypting: Cell<bool>,
    use_source: Cell<bool>,

    client: OptionalCell<&'static dyn CapsuleTestClient>,
}

pub struct TestAes128Ecb<'a, A: 'a> {
    aes: &'a A,

    key: TakeCell<'a, [u8]>,
    source: TakeCell<'static, [u8]>,
    data: TakeCell<'static, [u8]>,
    test_decrypt: bool,

    encrypting: Cell<bool>,
    use_source: Cell<bool>,

    client: OptionalCell<&'static dyn CapsuleTestClient>,
}

const DATA_OFFSET: usize = AES128_BLOCK_SIZE;
const DATA_LEN: usize = 4 * AES128_BLOCK_SIZE;

impl<'a, A: AES128<'a> + AES128ECB> TestAes128Ecb<'a, A> {
    pub fn new(
        aes: &'a A,
        key: &'a mut [u8],
        source: &'static mut [u8],
        data: &'static mut [u8],
        test_decrypt: bool,
    ) -> Self {
        TestAes128Ecb {
            aes,

            key: TakeCell::new(key),
            source: TakeCell::new(source),
            data: TakeCell::new(data),
            test_decrypt,

            encrypting: Cell::new(true),
            use_source: Cell::new(true),

            client: OptionalCell::empty(),
        }
    }

    pub fn run(&self) {
        self.aes.enable();

        self.aes.set_mode_aes128ecb(self.encrypting.get()).unwrap();

        // Copy key into key buffer and configure it in the hardware
        self.key.map(|key| {
            for (i, b) in KEY.iter().enumerate() {
                key[i] = *b;
            }

            assert!(self.aes.set_key(key) == Ok(()));
        });

        // Copy mode-appropriate source into source buffer
        let source_mode = if self.encrypting.get() {
            &PTXT
        } else {
            &CTXT_ECB
        };
        self.source.map(|source| {
            for (i, b) in source_mode.iter().enumerate() {
                source[i] = *b;
            }
        });

        if !self.use_source.get() {
            // Copy source into dest for in-place encryption
            self.source.map_or_else(
                || panic!("No source"),
                |source| {
                    self.data.map_or_else(
                        || panic!("No data"),
                        |data| {
                            for (i, b) in source.iter().enumerate() {
                                data[DATA_OFFSET + i] = *b;
                            }
                        },
                    );
                },
            );
        }

        self.aes.start_message();

        let start = DATA_OFFSET;
        let stop = DATA_OFFSET + DATA_LEN;

        match self.aes.crypt(
            if self.use_source.get() {
                self.source.take()
            } else {
                None
            },
            self.data.take().unwrap(),
            start,
            stop,
        ) {
            None => {
                // await crypt_done()
            }
            Some((result, source, dest)) => {
                self.source.put(source);
                self.data.put(Some(dest));
                panic!("crypt() failed: {:?}", result);
            }
        }
    }
}

impl<'a, A: AES128<'a> + AES128ECB> CapsuleTest for TestAes128Ecb<'a, A> {
    fn set_client(&self, client: &'static dyn CapsuleTestClient) {
        self.client.set(client);
    }
}

impl<'a, A: AES128<'a> + AES128Ctr> TestAes128Ctr<'a, A> {
    pub fn new(
        aes: &'a A,
        key: &'a mut [u8],
        iv: &'a mut [u8],
        source: &'static mut [u8],
        data: &'static mut [u8],
        test_decrypt: bool,
    ) -> Self {
        TestAes128Ctr {
            aes,

            key: TakeCell::new(key),
            iv: TakeCell::new(iv),
            source: TakeCell::new(source),
            data: TakeCell::new(data),
            test_decrypt,

            encrypting: Cell::new(true),
            use_source: Cell::new(true),

            client: OptionalCell::empty(),
        }
    }

    pub fn run(&self) {
        self.aes.enable();

        self.aes.set_mode_aes128ctr(self.encrypting.get()).unwrap();

        // Copy key into key buffer and configure it in the hardware
        self.key.map(|key| {
            for (i, b) in KEY.iter().enumerate() {
                key[i] = *b;
            }

            assert!(self.aes.set_key(key) == Ok(()));
        });

        // Copy mode-appropriate IV into IV buffer and configure it in the hardware
        self.iv.map(|iv| {
            let iv_mode = &IV_CTR;
            for (i, b) in iv_mode.iter().enumerate() {
                iv[i] = *b;
            }

            assert!(self.aes.set_iv(iv) == Ok(()));
        });

        // Copy mode-appropriate source into source buffer
        let source_mode = if self.encrypting.get() {
            &PTXT
        } else {
            &CTXT_CTR
        };
        self.source.map(|source| {
            for (i, b) in source_mode.iter().enumerate() {
                source[i] = *b;
            }
        });

        if !self.use_source.get() {
            // Copy source into dest for in-place encryption
            self.source.map_or_else(
                || panic!("No source"),
                |source| {
                    self.data.map_or_else(
                        || panic!("No data"),
                        |data| {
                            for (i, b) in source.iter().enumerate() {
                                data[DATA_OFFSET + i] = *b;
                            }
                        },
                    );
                },
            );
        }

        self.aes.start_message();

        let start = DATA_OFFSET;
        let stop = DATA_OFFSET + DATA_LEN;

        match self.aes.crypt(
            if self.use_source.get() {
                self.source.take()
            } else {
                None
            },
            self.data.take().unwrap(),
            start,
            stop,
        ) {
            None => {
                // await crypt_done()
            }
            Some((result, source, dest)) => {
                self.source.put(source);
                self.data.put(Some(dest));
                panic!("crypt() failed: {:?}", result);
            }
        }
    }
}

impl<'a, A: AES128<'a> + AES128Ctr> hil::symmetric_encryption::Client<'a> for TestAes128Ctr<'a, A> {
    fn crypt_done(&'a self, source: Option<&'static mut [u8]>, dest: &'static mut [u8]) {
        if self.use_source.get() {
            // Take back the source buffer
            self.source.put(source);
        }

        // Take back the destination buffer
        self.data.replace(dest);

        let expected = if self.encrypting.get() {
            &CTXT_CTR
        } else {
            &PTXT
        };

        if self.data.map_or(false, |data| {
            &data[DATA_OFFSET..DATA_OFFSET + DATA_LEN] == expected.as_ref()
        }) {
            debug!(
                "aes_test CTR passed: (CTR {} {} {})",
                if self.encrypting.get() { "Enc" } else { "Dec" },
                "Ctr",
                if self.use_source.get() {
                    "Src/Dst"
                } else {
                    "In-place"
                }
            );
        } else {
            panic!(
                "aes_test failed: (CTR {} {} {})",
                if self.encrypting.get() { "Enc" } else { "Dec" },
                "Ctr",
                if self.use_source.get() {
                    "Src/Dst"
                } else {
                    "In-place"
                }
            );
        }
        self.aes.disable();

        // Continue testing with other configurations
        if self.use_source.get() {
            self.use_source.set(false);
            self.run();
        } else {
            if self.encrypting.get() && self.test_decrypt {
                self.encrypting.set(false);
                self.use_source.set(true);
                self.run();
            } else {
                self.client.map(|client| {
                    client.done(Ok(()));
                });
            }
        }
    }
}

impl<'a, A: AES128<'a> + AES128Ctr> CapsuleTest for TestAes128Ctr<'a, A> {
    fn set_client(&self, client: &'static dyn CapsuleTestClient) {
        self.client.set(client);
    }
}

impl<'a, A: AES128<'a> + AES128CBC> TestAes128Cbc<'a, A> {
    pub fn new(
        aes: &'a A,
        key: &'a mut [u8],
        iv: &'a mut [u8],
        source: &'static mut [u8],
        data: &'static mut [u8],
        test_decrypt: bool,
    ) -> Self {
        TestAes128Cbc {
            aes,

            key: TakeCell::new(key),
            iv: TakeCell::new(iv),
            source: TakeCell::new(source),
            data: TakeCell::new(data),
            test_decrypt,

            encrypting: Cell::new(true),
            use_source: Cell::new(true),

            client: OptionalCell::empty(),
        }
    }

    pub fn run(&self) {
        self.aes.enable();

        self.aes.set_mode_aes128cbc(self.encrypting.get()).unwrap();

        // Copy key into key buffer and configure it in the hardware
        self.key.map(|key| {
            for (i, b) in KEY.iter().enumerate() {
                key[i] = *b;
            }

            assert!(self.aes.set_key(key) == Ok(()));
        });

        // Copy mode-appropriate IV into IV buffer and configure it in the hardware
        self.iv.map(|iv| {
            let iv_mode = &IV_CBC;

            for (i, b) in iv_mode.iter().enumerate() {
                iv[i] = *b;
            }

            assert!(self.aes.set_iv(iv) == Ok(()));
        });

        // Copy mode-appropriate source into source buffer
        let source_mode = if self.encrypting.get() {
            &PTXT
        } else {
            &CTXT_CBC
        };
        self.source.map(|source| {
            for (i, b) in source_mode.iter().enumerate() {
                source[i] = *b;
            }
        });

        if !self.use_source.get() {
            // Copy source into dest for in-place encryption
            self.source.map_or_else(
                || panic!("aes_test: no source"),
                |source| {
                    self.data.map_or_else(
                        || panic!("aes_test: no data"),
                        |data| {
                            for (i, b) in source.iter().enumerate() {
                                data[DATA_OFFSET + i] = *b;
                            }
                        },
                    );
                },
            );
        }

        self.aes.start_message();

        let start = DATA_OFFSET;
        let stop = DATA_OFFSET + DATA_LEN;

        match self.aes.crypt(
            if self.use_source.get() {
                self.source.take()
            } else {
                None
            },
            self.data.take().unwrap(),
            start,
            stop,
        ) {
            None => {
                // await crypt_done()
            }
            Some((result, source, dest)) => {
                self.source.put(source);
                self.data.put(Some(dest));
                panic!("crypt() failed: {:?}", result);
            }
        }
    }
}

impl<'a, A: AES128<'a> + AES128CBC> hil::symmetric_encryption::Client<'a> for TestAes128Cbc<'a, A> {
    fn crypt_done(&'a self, source: Option<&'static mut [u8]>, dest: &'static mut [u8]) {
        if self.use_source.get() {
            // Take back the source buffer
            self.source.put(source);
        }

        // Take back the destination buffer
        self.data.replace(dest);

        let expected = if self.encrypting.get() {
            &CTXT_CBC
        } else {
            &PTXT
        };

        if self.data.map_or(false, |data| {
            &data[DATA_OFFSET..DATA_OFFSET + DATA_LEN] == expected.as_ref()
        }) {
            debug!(
                "aes_test passed (CBC {} {})",
                if self.encrypting.get() { "Enc" } else { "Dec" },
                if self.use_source.get() {
                    "Src/Dst"
                } else {
                    "In-place"
                }
            );
        } else {
            panic!(
                "aes_test failed: (CBC {} {})",
                if self.encrypting.get() { "Enc" } else { "Dec" },
                if self.use_source.get() {
                    "Src/Dst"
                } else {
                    "In-place"
                }
            );
        }
        self.aes.disable();

        // Continue testing with other configurations
        if self.use_source.get() {
            self.use_source.set(false);
            self.run();
        } else {
            if self.encrypting.get() && self.test_decrypt {
                self.encrypting.set(false);
                self.use_source.set(true);
                self.run();
            } else {
                self.client.map(|client| {
                    client.done(Ok(()));
                });
            }
        }
    }
}

impl<'a, A: AES128<'a> + AES128CBC> CapsuleTest for TestAes128Cbc<'a, A> {
    fn set_client(&self, client: &'static dyn CapsuleTestClient) {
        self.client.set(client);
    }
}

impl<'a, A: AES128<'a> + AES128ECB> hil::symmetric_encryption::Client<'a> for TestAes128Ecb<'a, A> {
    fn crypt_done(&'a self, source: Option<&'static mut [u8]>, dest: &'static mut [u8]) {
        if self.use_source.get() {
            // Take back the source buffer
            self.source.put(source);
        }

        // Take back the destination buffer
        self.data.replace(dest);

        let expected = if self.encrypting.get() {
            &CTXT_ECB
        } else {
            &PTXT
        };

        if self.data.map_or(false, |data| {
            &data[DATA_OFFSET..DATA_OFFSET + DATA_LEN] == expected.as_ref()
        }) {
            debug!(
                "aes_test passed (ECB {} {})",
                if self.encrypting.get() { "Enc" } else { "Dec" },
                if self.use_source.get() {
                    "Src/Dst"
                } else {
                    "In-place"
                }
            );
        } else {
            panic!(
                "aes_test failed: (ECB {} {})",
                if self.encrypting.get() { "Enc" } else { "Dec" },
                if self.use_source.get() {
                    "Src/Dst"
                } else {
                    "In-place"
                }
            );
        }
        self.aes.disable();

        // Continue testing with other configurations
        if self.use_source.get() {
            self.use_source.set(false);
            self.run();
        } else {
            if self.encrypting.get() && self.test_decrypt {
                self.encrypting.set(false);
                self.use_source.set(true);
                self.run();
            } else {
                self.client.map(|client| {
                    client.done(Ok(()));
                });
            }
        }
    }
}

#[rustfmt::skip]
const KEY: [u8; AES128_KEY_SIZE] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
];

#[rustfmt::skip]
const IV_CTR: [u8; AES128_BLOCK_SIZE] = [
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
];

#[rustfmt::skip]
const IV_CBC: [u8; AES128_BLOCK_SIZE] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
];

#[rustfmt::skip]
const PTXT: [u8; 4 * AES128_BLOCK_SIZE] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
];

#[rustfmt::skip]
const CTXT_CTR: [u8; 4 * AES128_BLOCK_SIZE] = [
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
    0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
    0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
    0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
    0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
    0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
    0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
];

#[rustfmt::skip]
const CTXT_CBC: [u8; 4 * AES128_BLOCK_SIZE] = [
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
    0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
    0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
];

#[rustfmt::skip]
const CTXT_ECB: [u8; 4 * AES128_BLOCK_SIZE] = [
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
    0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
    0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
    0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
    0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
    0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
    0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
];
