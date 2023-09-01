/// author: Jean-Roland Gosse
/// desc: Light Command Set Format error module
///
/// This file is part of LCSF Stack Rust.
/// You should have received a copy of the GNU Lesser General Public License
/// along with this program. If not, see <https://www.gnu.org/licenses/>

use lazy_static::lazy_static;

use crate::lcsf_transcoder;
use crate::lcsf_validator;
use lcsf_transcoder::LcsfModeEnum;
use lcsf_transcoder::LcsfRawMsg;
use lcsf_transcoder::LcsfRawAtt;
use lcsf_transcoder::LcsfRawAttPayload;

use lcsf_validator::LcsfProtDesc;
use lcsf_validator::LcsfCmdDesc;
use lcsf_validator::LcsfAttDesc;
use lcsf_validator::LcsfDataType;
use lcsf_validator::LcsfValidCmd;
use lcsf_validator::LcsfValidAttPayload;

// *** Types ***

// Lcsf error protocol (Lcsf ep) id
pub const LCSF_EP_PROT_ID_NORMAL:u16 = 0xFFFF;
pub const LCSF_EP_PROT_ID_SMALL:u16 = 0x00FF;

// Lcsf ep attribute location values
pub enum LcsfEpLocEnum {
    DecodeError = 0x00,
    ValidationError = 0x01,
}

// LCSF_EP protocol description
lazy_static! {
    pub static ref LCSF_EP_PROT_DESC:LcsfProtDesc = LcsfProtDesc {
        cmd_desc_arr: vec![
            (0x00, LcsfCmdDesc {
                att_desc_arr: vec![
                    (0x00, LcsfAttDesc {
                        is_optional: false,
                        data_type: LcsfDataType::Uint8,
                        subatt_desc_arr: Vec::new(),
                    }),
                    (0x01, LcsfAttDesc {
                        is_optional: false,
                        data_type: LcsfDataType::Uint8,
                        subatt_desc_arr: Vec::new(),
                    }),
                ]
            }),
        ]
    };
}

// LCSF_EP constants
const LCSF_EP_ERR_CMD_ID:u16 = 0x0000;
const LCSF_EP_LOC_ATT_ID:u16 = 0x0000;
const LCSF_EP_TYPE_ATT_ID:u16 = 0x0001;
const LCSF_EP_ERR_CMD_ATT_NB:u16 = 2;

/// Encode a lcsf error message into a buffer
/// \param lcsf_mode encoding mode value
/// \param errorLoc location of the error encountered
/// \param errorType type of the error encountered
pub fn encode_error(lcsf_mode:LcsfModeEnum, error_loc:LcsfEpLocEnum, error_type:u8) -> Vec<u8> {
    // Init protocol id
    let mut prot_id:u16 = LCSF_EP_PROT_ID_NORMAL;
    if lcsf_mode == LcsfModeEnum::Small {
        prot_id = LCSF_EP_PROT_ID_SMALL;
    }
    // Create raw message
    let error_msg = LcsfRawMsg {
        prot_id: prot_id,
        cmd_id: LCSF_EP_ERR_CMD_ID,
        att_nb: LCSF_EP_ERR_CMD_ATT_NB,
        att_arr: vec![
            (LCSF_EP_LOC_ATT_ID, LcsfRawAtt {
                has_subatt: false,
                payload_size: 1,
                payload: LcsfRawAttPayload::Data(vec![error_loc as u8]),
            }),
            (LCSF_EP_TYPE_ATT_ID, LcsfRawAtt {
                has_subatt: false,
                payload_size: 1,
                payload: LcsfRawAttPayload::Data(vec![error_type]),
            }),
        ],
    };
    // Encode the message with transcoder
    return lcsf_transcoder::encode_buff(lcsf_mode, &error_msg);
}

#[cfg(test)]
use lcsf_transcoder::LcsfDecodeErrorEnum;
#[cfg(test)]
use lcsf_validator::LcsfValidateErrorEnum;

#[test]
pub fn test_encode_error() {
    // Test data
    let buff_small:Vec<u8> = vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x05];
    let buff_normal:Vec<u8> = vec![0xff, 0xff, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
                            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
    assert_eq!(buff_small, encode_error(LcsfModeEnum::Small, LcsfEpLocEnum::ValidationError,
        LcsfValidateErrorEnum::WrongAttDataType as u8));
    assert_eq!(buff_normal, encode_error(LcsfModeEnum::Normal, LcsfEpLocEnum::DecodeError,
        LcsfDecodeErrorEnum::FormatErr as u8));
}

/// Process a lcsf error message
/// \param valid_cmd validated error message reference
pub fn process_error(valid_cmd:&LcsfValidCmd) {
    let mut err_loc = 0;
    let mut err_type = 0;
    // Retrieve error information
    if let LcsfValidAttPayload::Data(data) = &valid_cmd.att_arr[LCSF_EP_LOC_ATT_ID as usize].payload {
        err_loc = data[0];
    };
    if let LcsfValidAttPayload::Data(data) = &valid_cmd.att_arr[LCSF_EP_TYPE_ATT_ID as usize].payload {
        err_type = data[0];
    };
    // Turn enum into string
    let type_str:&str;
    let loc_str = match err_loc {
        0 => "Decoder",
        1 => "Validator",
        _ => "Unknown",
    };
    if err_loc == 0 {
        type_str = match err_type {
            0 => "Bad format",
            1 => "Overflow",
            _ => "Unknown",
        };
    } else {
        type_str = match err_type {
            0 => "Unknown protocol id",
            1 => "Unknown command id",
            2 => "Unknown attribute id",
            3 => "Too many attributes received",
            4 => "Missing mandatory attribute",
            5 => "Wrong attribute data type",
            _ => "Unknown",
        };
    }
    // Notify the error
    println!("[lcsf_error]: Received error, location: {loc_str}, type: {type_str}");
}