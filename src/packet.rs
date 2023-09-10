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

/// Called by protocols to send commands via LcsfCore
///
/// prot_id: protocol id of the command
///
/// valid_cmd: valid command reference
pub fn prot_send_cmd(prot_id: u16, valid_cmd: &LcsfValidCmd) {
    let core = CORE.read().unwrap();
    core.send_cmd(prot_id, valid_cmd);
}

/// Initialize the protocols in LcsfCore
pub fn prot_init() {
    let mut core = CORE.write().unwrap();
    protocol_test::init_core(&mut core);
    // Add more protocols here
    drop(core);
}

/// Called by LcsfCore to send lcsf buffer where they need to do
fn example_send(pkt: &[u8]) {
    println!("packet to send: {pkt:?}");
}

/// Custom function called when an lcsf error message is received
#[allow(dead_code)]
fn example_err_cb(cmd: &LcsfValidCmd) {
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

    // Update err callback (optional, only if you want to handle error message)
    // let mut mut_core = CORE.write().unwrap();
    // mut_core.update_err_cb(example_err_cb);
    // drop(mut_core);

    // Init protocols in core
    prot_init();
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
fn dummy_process(cmd: &LcsfValidCmd) {
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
    // Add protocol
    lcsf_core.add_protocol(0xab, &EXAMPLE_DESC, dummy_process);
    // Receive buffer
    println!("Input buffer: {example_buff:?}");
    lcsf_core.receive_buff(&example_buff);
    // Send command
    println!("Input command: {example_valid_cmd:?}");
    lcsf_core.send_cmd(0xab, &example_valid_cmd);
    // Update err callback (optional, only if you want to handle error message)
    lcsf_core.update_err_cb(example_err_cb);
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

    #[test]
    fn test_prot_init() {
        prot_init();
    }
}
