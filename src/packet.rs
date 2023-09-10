//! Example main on how to use the lcsf lib
//!
//! author: Jean-Roland Gosse
//!
//! This file is part of LCSF Stack Rust.
//! Spec details at <https://jean-roland.github.io/LCSF_Doc/>
//! You should have received a copy of the GNU Lesser General Public License
//! along with this program. If not, see <https://www.gnu.org/licenses/>

use crate::lcsf_lib::lcsf_core;
use crate::lcsf_lib::lcsf_error;
use crate::lcsf_lib::lcsf_transcoder;
use crate::lcsf_lib::lcsf_validator;
use crate::lcsf_prot::protocol_test;
use lazy_static::lazy_static;
use lcsf_core::LcsfCore;
use lcsf_transcoder::LcsfModeEnum;
use lcsf_validator::LcsfValidCmd;
use std::sync::RwLock;

// *** Using LcsfGenerator ***

lazy_static! {
    /// Static LcsfCore reference to handle lcsf message processing
    static ref CORE: RwLock<LcsfCore> = RwLock::new(LcsfCore::new(LcsfModeEnum::Small, example_send, false));
}

/// Called by LcsfCore to send lcsf buffer where they need to do
fn example_send(pkt: &[u8]) {
    println!("packet to send: {pkt:?}");
}

/// Custom function called when an lcsf error message is received
#[allow(dead_code)]
fn example_err_cb(_: &LcsfCore, cmd: &LcsfValidCmd) {
    let (loc_str, type_str) = lcsf_error::process_error(cmd);
    println!("Custom function received error, location: {loc_str}, type: {type_str}");
}

/// Example use of LCSF when using LcsfGenerator
pub fn example_use_gen() {
    // Example data
    let example_buff: Vec<u8> = vec![0x55, 0x01, 0x00];
    let err_buff: Vec<u8> = vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01];
    let bad_data: Vec<u8> = vec![0x55, 0x05, 0x00];

    println!("*** Example use with generator ***");

    let mut mut_core = CORE.write().unwrap();

    // Init protocols in core
    protocol_test::init_core(&mut mut_core);
    // (Add more protocols here)

    // Update err callback (optional, only if you want to handle error message)
    // mut_core.update_err_cb(example_err_cb);

    drop(mut_core);
    // Receive buffer
    println!("Input buffer: {example_buff:?}");
    let core = CORE.read().unwrap();
    core.receive_buff(&example_buff);
    // Receive error
    println!("Input error: {err_buff:?}");
    core.receive_buff(&err_buff);
    // Receive bad data
    println!("Input bad date: {bad_data:?}");
    core.receive_buff(&bad_data);
}

// *** Without LcsfGenerator ***
use crate::lcsf_lib::lcsf_validator::LcsfAttDesc;
use crate::lcsf_lib::lcsf_validator::LcsfCmdDesc;
use crate::lcsf_lib::lcsf_validator::LcsfDataType;
use crate::lcsf_lib::lcsf_validator::LcsfProtDesc;
use crate::lcsf_lib::lcsf_validator::LcsfValidAtt;
use crate::lcsf_lib::lcsf_validator::LcsfValidAttPayload;

lazy_static! {
    /// Example descriptor
    static ref EXAMPLE_DESC:LcsfProtDesc = LcsfProtDesc {
        cmd_desc_arr: vec![
            (0x12, LcsfCmdDesc {
                att_desc_arr: vec![
                    (0x55, LcsfAttDesc {
                        is_optional: false,
                        data_type: LcsfDataType::ByteArray,
                        subatt_desc_arr: Vec::new(),
                    }),
                ]
            }),
        ]
    };
}

/// Function called when a protocol received a valid command
fn dummy_process(_: &LcsfCore, cmd: &LcsfValidCmd) {
    if let LcsfValidAttPayload::Data(data) = &cmd.att_arr[0].payload {
        println!(
            "[Protocol 0xab handle]: Command received:, id: {}, data: {:?}",
            cmd.cmd_id, data
        );
    };
}

/// Example use without Lcsf_Generator
#[allow(dead_code)]
pub fn example_use_other() {
    // Example data
    let example_valid_cmd = LcsfValidCmd {
        cmd_id: 0x12,
        att_arr: vec![LcsfValidAtt {
            payload: LcsfValidAttPayload::Data(vec![0x00, 0x01, 0x02, 0x03, 0x04]),
        }],
    };
    let example_buff: Vec<u8> = vec![0xab, 0x12, 0x01, 0x55, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
    let err_buff: Vec<u8> = vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01];
    let bad_data: Vec<u8> = vec![0xab, 0x10, 0x00];
    println!("\n*** Example use without generator ***");
    // Create lcsf core
    let mut lcsf_core = LcsfCore::new(LcsfModeEnum::Small, example_send, true);

    // Update err callback (optional, only if you want to handle error message)
    // lcsf_core.update_err_cb(example_err_cb);

    // Add protocol
    lcsf_core.add_protocol(0xab, &EXAMPLE_DESC, dummy_process);
    // Receive buffer
    println!("Input buffer: {example_buff:?}");
    lcsf_core.receive_buff(&example_buff);
    // Send command
    println!("Input command: {example_valid_cmd:?}");
    lcsf_core.send_cmd(0xab, &example_valid_cmd);
    // Receive error
    println!("Input error: {err_buff:?}");
    lcsf_core.receive_buff(&err_buff);
    // Receive bad data
    println!("Input bad date: {bad_data:?}");
    lcsf_core.receive_buff(&bad_data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Test status variables
    static ERR_TEST_STATUS: AtomicUsize = AtomicUsize::new(0);
    static SEND_TEST_STATUS: AtomicUsize = AtomicUsize::new(0);

    lazy_static! {
        /// Static LcsfCore reference to handle lcsf message processing
        static ref TEST_CORE: RwLock<LcsfCore> = RwLock::new(LcsfCore::new(LcsfModeEnum::Small, test_send, true));

        // Test data
        static ref ERR_FORMAT_MSG: Vec<u8> =
            vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00];
        static ref ERR_OVERFLOW_MSG: Vec<u8> =
            vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01];
        static ref ERR_UNK_PROT_MSG: Vec<u8> =
            vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00];
        static ref ERR_UNK_CMD_MSG: Vec<u8> =
            vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01];
        static ref ERR_UNK_ATT_MSG: Vec<u8> =
            vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02];
        static ref ERR_TOO_MANY_ATT_MSG: Vec<u8> =
            vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x03];
        static ref ERR_MISS_ATT_MSG: Vec<u8> =
            vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x04];
        static ref ERR_WRONG_DATA_TYPE_MSG: Vec<u8> =
            vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x05];
        // Wrong messages
        static ref BAD_FORMAT_MSG: Vec<u8> = vec![0x55, 0x00, 0x05];
        static ref BAD_PROT_ID_MSG: Vec<u8> = vec![0x21, 0x00, 0x00];
        static ref BAD_CMD_ID_MSG: Vec<u8> = vec![0x55, 0x4c, 0x00];
        static ref BAD_ATT_ID_MSG: Vec<u8> = vec![
            0x55, 0x04, 0x06, // CC2
            0x00, 0x01, 0x00, // SA1
            0x01, 0x02, 0x00, 0x00, // SA2
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00, // SA3
            0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // SA4
            0x04, 0x01, 0x00, // SA5
            0x48, 0x01, 0x00, // Wrong att
        ];
        static ref EXTRA_ATT_MSG: Vec<u8> = vec![0x55, 0x00, 0x01, 0x00, 0x01, 0x00];
        static ref MISS_ATT_MSG: Vec<u8> = vec![
            0x55, 0x04, 0x05, // CC2
            0x00, 0x01, 0x00, // SA1
            0x01, 0x02, 0x00, 0x00, // SA2
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00, // SA3
            0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // SA4
            0x05, 0x01, 0x00, // SA6
        ];
        static ref BAD_DATA_TYPE_MSG: Vec<u8> = vec![
            0x55, 0x04, 0x05, // CC2
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // SA1
            0x01, 0x02, 0x00, 0x00, // SA2
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00, // SA3
            0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // SA4
            0x04, 0x01, 0x00, // SA5
        ];
        static ref BAD_SUBATT_ID_MSG: Vec<u8> = vec![
            0x55, 0x07, 0x03, // CC5
            0x01, 0x02, 0x11, 0x02, // SA2
            0x8a, 0x02, // CA5
            0x00, 0x01, 0x23, // CA5_SA1
            0x01, 0x02, 0x0f, 0x20, // CA5_SA2
            0x8b, 0x02, // CA6
            0x01, 0x01, 0xa9, // BAD_CA6_SA1
            0x8b, 0x01, // CA6_CA7
            0x8a, 0x01, // CA7_CA8
            0x03, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // CA8_SA4
        ];
        static ref EXTRA_SUBATT_MSG: Vec<u8> = vec![
            0x55, 0x07, 0x03, // CC5
            0x01, 0x02, 0x11, 0x02, // SA2
            0x8a, 0x02, // CA5
            0x00, 0x01, 0x23, // CA5_SA1
            0x01, 0x02, 0x0f, 0x20, // CA5_SA2
            0x8b, 0x03, // CA6
            0x00, 0x01, 0xa9, // CA6_SA1
            0x01, 0x01, 0xa9, // Extra CA6 att
            0x8b, 0x01, // CA6_CA7
            0x8a, 0x01, // CA7_CA8
            0x03, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // CA8_SA4
        ];
        static ref MISS_SUBATT_MSG: Vec<u8> = vec![
            0x55, 0x07, 0x03, // CC5
            0x01, 0x02, 0x11, 0x02, // SA2
            0x8a, 0x02, // CA5
            0x00, 0x01, 0x23, // CA5_SA1
            0x01, 0x02, 0x0f, 0x20, // CA5_SA2
            0x8b, 0x02, // CA6
            0x00, 0x01, 0xa9, // CA6_SA1
            0x8b, 0x01, // CA6_CA7
            0x00, 0x01, 0xa9, // CA7_SA1
        ];
        static ref BAD_SUBATT_DATA_TYPE_MSG: Vec<u8> = vec![
            0x55, 0x07, 0x03, // CC5
            0x01, 0x02, 0x11, 0x02, // SA2
            0x8a, 0x02, // CA5
            0x00, 0x01, 0x23, // CA5_SA1
            0x01, 0x02, 0x0f, 0x20, // CA5_SA2
            0x8b, 0x02, // CA6
            0x00, 0x02, 0xa9, 0x01, // CA6_SA1
            0x8b, 0x01, // CA6_CA7
            0x03, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // CA8_SA4
        ];
        // Test messages
        static ref SC1_MSG: Vec<u8> = vec![0x55, 0x00, 0x00];
        static ref SC2_MSG: Vec<u8> = vec![0x55, 0x01, 0x00];
        static ref SC3_MSG: Vec<u8> = vec![0x55, 0x02, 0x00];
        static ref CC1_MSG: Vec<u8> = vec![
            0x55, 0x03, 0x09, // CC1
            0x00, 0x01, 0x01, // SA1
            0x01, 0x02, 0xD1, 0x07, // SA2
            0x02, 0x04, 0xa1, 0x86, 0x01, 0x00, // SA3
            0x03, 0x05, 0x06, 0x05, 0x04, 0x03, 0x02, // SA4
            0x04, 0x04, 0x62, 0x6f, 0x42, 0x00, // SA5
            0x05, 0x01, 0x04, // SA6
            0x07, 0x04, 0xf0, 0x49, 0x02, 0x00, // SA8
            0x08, 0x05, 0x02, 0x03, 0x04, 0x05, 0x06, // SA9
            0x09, 0x05, 0x6c, 0x75, 0x61, 0x50, 0x00, // SA10
        ];
        static ref CC2_MSG: Vec<u8> = vec![
            0x55, 0x04, 0x09, // CC2
            0x00, 0x01, 0x00, // SA1
            0x01, 0x02, 0xD0, 0x07, // SA2
            0x02, 0x04, 0xa0, 0x86, 0x01, 0x00, // SA3
            0x03, 0x05, 0x05, 0x04, 0x03, 0x02, 0x01, // SA4
            0x04, 0x04, 0x42, 0x6f, 0x62, 0x00, // SA5
            0x05, 0x01, 0x03, // SA6
            0x07, 0x04, 0xef, 0x49, 0x02, 0x00, // SA8
            0x08, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, // SA9
            0x09, 0x05, 0x50, 0x61, 0x75, 0x6c, 0x00, // SA10
        ];
        static ref CC3_MSG_OUT: Vec<u8> = vec![
            0x55, 0x05, 0x07, // CC3
            0x00, 0x01, 0x00, // SA1
            0x01, 0x02, 0x00, 0x00, // SA2
            0x02, 0x04, 0xef, 0x49, 0x6a, 0x43, // SA3
            0x03, 0x05, 0x55, 0xaa, 0x55, 0xaa, 0x55, // SA4
            0x04, 0x10, 0x46, 0x6f, 0x77, 0x6c, 0x65, 0x72, 0x2d, 0x4e, 0x6f, 0x72, 0x64, 0x68, 0x65, 0x69, 0x6d, 0x00, // SA5
            0x06, 0x02, 0x00, 0x00, // SA7
            0x08, 0x05, 0x00, 0xff, 0x00, 0xff, 0x00, // SA9
        ];
        static ref CC3_MSG_IN: Vec<u8> = vec![
            0x55, 0x05, 0x07, // CC3
            0x00, 0x01, 0xff, // SA1
            0x01, 0x02, 0xff, 0xff, // SA2
            0x02, 0x04, 0xee, 0x49, 0x6a, 0x43, // SA3
            0x03, 0x05, 0x54, 0xa9, 0x54, 0xa9, 0x54, // SA4
            0x04, 0x10, 0x6d, 0x69, 0x65, 0x68, 0x64, 0x72, 0x6f, 0x4e, 0x2d, 0x72, 0x65, 0x6c, 0x77, 0x6f, 0x46, 0x00, // SA5
            0x06, 0x02, 0xff, 0xff, // SA7
            0x08, 0x05, 0xff, 0xfe, 0xff, 0xfe, 0xff, // SA9
        ];
        static ref CC4_MSG: Vec<u8> = vec![
            0x55, 0x06, 0x03, // CC4
            0x00, 0x01, 0x12, // SA1
            0x8a, 0x02, // CA1
            0x00, 0x01, 0x24, // CA1_SA1
            0x01, 0x02, 0x10, 0x20, // CA1_SA2
            0x8b, 0x02, // CA2
            0x00, 0x01, 0xaa, // CA2_SA1
            0x8b, 0x01, // CA2_CA3
            0x8a, 0x01, // CA3_CA4
            0x03, 0x05, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // CA4_SA4
        ];
        static ref CC5_MSG: Vec<u8> = vec![
            0x55, 0x07, 0x03, // CC5
            0x01, 0x02, 0x11, 0x02, // SA2
            0x8a, 0x02, // CA5
            0x00, 0x01, 0x23, // CA5_SA1
            0x01, 0x02, 0x0f, 0x20, // CA5_SA2
            0x8b, 0x02, // CA6
            0x00, 0x01, 0xa9, // CA6_SA1
            0x8b, 0x01, // CA6_CA7
            0x8a, 0x01, // CA7_CA8
            0x03, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // CA8_SA4
        ];
        static ref CC6_MSG_OUT: Vec<u8> = vec![
            0x55, 0x08, 0x02, // CC6
            0x03, 0x05, 0x41, 0x02, 0x81, 0x0a, 0xc0, // SA4
            0x8a, 0x03, // CA9
            0x00, 0x01, 0x23, // CA9_SA1
            0x01, 0x02, 0x61, 0x2c, // CA9_SA2
            0x02, 0x04, 0x21, 0x14, 0x00, 0xa2, // CA9_SA3
        ];
        static ref CC6_MSG_IN: Vec<u8> = vec![
            0x55, 0x08, 0x02, // CC6
            0x03, 0x05, 0x40, 0x01, 0x80, 0x09, 0xbf, // SA4
            0x8a, 0x03, // CA9
            0x00, 0x01, 0x22, // CA9_SA1
            0x01, 0x02, 0x60, 0x2c, // CA9_SA2
            0x02, 0x04, 0x20, 0x14, 0x00, 0xa2, // CA9_SA3
        ];
    }

    fn test_send(pkt: &[u8]) {
        match SEND_TEST_STATUS.load(Ordering::SeqCst) {
            0 => {
                if *pkt == *ERR_FORMAT_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            1 => {
                if *pkt == *ERR_UNK_PROT_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            2 => {
                if *pkt == *ERR_UNK_CMD_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            3 => {
                if *pkt == *ERR_UNK_ATT_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            4 => {
                if *pkt == *ERR_TOO_MANY_ATT_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            5 => {
                if *pkt == *ERR_MISS_ATT_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            6 => {
                if *pkt == *ERR_WRONG_DATA_TYPE_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            7 => {
                if *pkt == *ERR_UNK_ATT_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            8 => {
                if *pkt == *ERR_TOO_MANY_ATT_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            9 => {
                if *pkt == *ERR_MISS_ATT_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            10 => {
                if *pkt == *ERR_WRONG_DATA_TYPE_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            11 => {
                if *pkt == *SC1_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            12 => {
                if *pkt == *SC3_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            13 => {
                if *pkt == *CC1_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            14 => {
                if *pkt == *CC3_MSG_OUT {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            15 => {
                if *pkt == *CC4_MSG {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            16 => {
                if *pkt == *CC6_MSG_OUT {
                    SEND_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            _ => {}
        }
    }

    fn test_err_cb(_: &LcsfCore, cmd: &LcsfValidCmd) {
        let (loc_str, type_str) = lcsf_error::process_error(cmd);
        match ERR_TEST_STATUS.load(Ordering::SeqCst) {
            0 => {
                if loc_str == "Decoder" && type_str == "Bad format" {
                    ERR_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            1 => {
                if loc_str == "Decoder" && type_str == "Overflow" {
                    ERR_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            2 => {
                if loc_str == "Validator" && type_str == "Unknown protocol id" {
                    ERR_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            3 => {
                if loc_str == "Validator" && type_str == "Unknown command id" {
                    ERR_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            4 => {
                if loc_str == "Validator" && type_str == "Unknown attribute id" {
                    ERR_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            5 => {
                if loc_str == "Validator" && type_str == "Too many attributes received" {
                    ERR_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            6 => {
                if loc_str == "Validator" && type_str == "Missing mandatory attribute" {
                    ERR_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            7 => {
                if loc_str == "Validator" && type_str == "Wrong attribute data type" {
                    ERR_TEST_STATUS.fetch_add(1, Ordering::SeqCst);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn test_fullstack() {
        // Init protocol
        let mut mut_core = TEST_CORE.write().unwrap();
        protocol_test::init_core(&mut mut_core);
        mut_core.update_err_cb(test_err_cb);
        drop(mut_core);
        let core = TEST_CORE.read().unwrap();

        // Test received errors
        assert_eq!(ERR_TEST_STATUS.load(Ordering::SeqCst), 0);
        core.receive_buff(&ERR_FORMAT_MSG);
        assert_eq!(ERR_TEST_STATUS.load(Ordering::SeqCst), 1);
        core.receive_buff(&ERR_OVERFLOW_MSG);
        assert_eq!(ERR_TEST_STATUS.load(Ordering::SeqCst), 2);
        core.receive_buff(&ERR_UNK_PROT_MSG);
        assert_eq!(ERR_TEST_STATUS.load(Ordering::SeqCst), 3);
        core.receive_buff(&ERR_UNK_CMD_MSG);
        assert_eq!(ERR_TEST_STATUS.load(Ordering::SeqCst), 4);
        core.receive_buff(&ERR_UNK_ATT_MSG);
        assert_eq!(ERR_TEST_STATUS.load(Ordering::SeqCst), 5);
        core.receive_buff(&ERR_TOO_MANY_ATT_MSG);
        assert_eq!(ERR_TEST_STATUS.load(Ordering::SeqCst), 6);
        core.receive_buff(&ERR_MISS_ATT_MSG);
        assert_eq!(ERR_TEST_STATUS.load(Ordering::SeqCst), 7);
        core.receive_buff(&ERR_WRONG_DATA_TYPE_MSG);
        assert_eq!(ERR_TEST_STATUS.load(Ordering::SeqCst), 8);

        // Test generated errors
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 0);
        core.receive_buff(&BAD_FORMAT_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 1);
        core.receive_buff(&BAD_PROT_ID_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 2);
        core.receive_buff(&BAD_CMD_ID_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 3);
        core.receive_buff(&BAD_ATT_ID_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 4);
        core.receive_buff(&EXTRA_ATT_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 5);
        core.receive_buff(&MISS_ATT_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 6);
        core.receive_buff(&BAD_DATA_TYPE_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 7);
        core.receive_buff(&BAD_SUBATT_ID_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 8);
        core.receive_buff(&EXTRA_SUBATT_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 9);
        core.receive_buff(&MISS_SUBATT_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 10);
        core.receive_buff(&BAD_SUBATT_DATA_TYPE_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 11);

        // Test valid packet
        core.receive_buff(&SC2_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 12);
        core.receive_buff(&SC3_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 13);
        core.receive_buff(&CC2_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 14);
        core.receive_buff(&CC3_MSG_IN);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 15);
        core.receive_buff(&CC5_MSG);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 16);
        core.receive_buff(&CC6_MSG_IN);
        assert_eq!(SEND_TEST_STATUS.load(Ordering::SeqCst), 17);
    }
}
