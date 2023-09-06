/// author: Jean-Roland Gosse
/// desc: Example main
///
/// This file is part of LCSF Stack Rust.
/// Spec details at https://jean-roland.github.io/LCSF_Doc/
/// You should have received a copy of the GNU Lesser General Public License
/// along with this program. If not, see <https://www.gnu.org/licenses/>
use lazy_static::lazy_static;

mod lcsf_lib;
use lcsf_lib::lcsf_core::LcsfCore;
use lcsf_lib::lcsf_error;
use lcsf_lib::lcsf_transcoder::LcsfModeEnum;
use lcsf_lib::lcsf_validator::LcsfAttDesc;
use lcsf_lib::lcsf_validator::LcsfCmdDesc;
use lcsf_lib::lcsf_validator::LcsfDataType;
use lcsf_lib::lcsf_validator::LcsfProtDesc;
use lcsf_lib::lcsf_validator::LcsfValidAtt;
use lcsf_lib::lcsf_validator::LcsfValidAttPayload;
use lcsf_lib::lcsf_validator::LcsfValidCmd;

lazy_static! {
    // Example descriptor
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

// Function called when a protocol received a valid command
fn example_process(cmd: LcsfValidCmd) {
    if let LcsfValidAttPayload::Data(data) = &cmd.att_arr[0].payload {
        println!(
            "[Protocol 0xab handle]: Command received:, id: {}, data: {:?}",
            cmd.cmd_id, data
        );
    };
}

// Custom function called when an lcsf error message is received
#[allow(dead_code)]
fn example_err_cb(cmd: LcsfValidCmd) {
    let (loc_str, type_str) = lcsf_error::process_error(&cmd);
    println!("Custom function received error, location: {loc_str}, type: {type_str}");
}

// Function called when protocol sends a message
fn example_send(buff: Vec<u8>) {
    println!("Buffer to send: {buff:?}");
}

// Main
fn main() {
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

    // Create lcsf core
    let mut lcsf_core = LcsfCore::new(LcsfModeEnum::Small, example_send, true);
    // Add protocol
    lcsf_core.add_protocol(0xab, &EXAMPLE_DESC, example_process);
    // Receive buffer
    println!("Input buffer: {example_buff:?}");
    lcsf_core.receive_buff(&example_buff);
    // Send command
    println!("Input command: {example_valid_cmd:?}");
    lcsf_core.send_cmd(0xab, &example_valid_cmd);
    // Update err callback (optional, only if you want to handle error message)
    // lcsf_core.update_err_cb(example_err_cb);
    // Receive error
    println!("Input error: {err_buff:?}");
    lcsf_core.receive_buff(&err_buff);
    // Receive bad data
    println!("Input bad date: {bad_data:?}");
    lcsf_core.receive_buff(&bad_data);
}
