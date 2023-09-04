/// author: Jean-Roland Gosse
/// desc: Light Command Set Format error module
///
/// This file is part of LCSF Stack Rust.
/// Spec info at https://jean-roland.github.io/LCSF_Doc/
/// You should have received a copy of the GNU Lesser General Public License
/// along with this program. If not, see <https://www.gnu.org/licenses/>
// Imports
use lazy_static::lazy_static;

use crate::lcsf_transcoder;
use crate::lcsf_validator;
use lcsf_transcoder::LcsfModeEnum;
use lcsf_transcoder::LcsfRawAtt;
use lcsf_transcoder::LcsfRawAttPayload;
use lcsf_transcoder::LcsfRawMsg;
use lcsf_validator::LcsfAttDesc;
use lcsf_validator::LcsfCmdDesc;
use lcsf_validator::LcsfDataType;
use lcsf_validator::LcsfProtDesc;
use lcsf_validator::LcsfValidAttPayload;
use lcsf_validator::LcsfValidCmd;

// Lcsf error protocol (Lcsf ep) id
pub const LCSF_EP_PROT_ID_NORMAL: u16 = 0xFFFF;
pub const LCSF_EP_PROT_ID_SMALL: u16 = 0x00FF;

// Lcsf ep attribute location values
pub enum LcsfEpLocEnum {
    DecodeError = 0x00,
    ValidationError = 0x01,
}

// Lcsf ep protocol description
lazy_static! {
    pub static ref LCSF_EP_PROT_DESC: LcsfProtDesc = LcsfProtDesc {
        cmd_desc_arr: vec![(
            0x00,
            LcsfCmdDesc {
                att_desc_arr: vec![
                    (
                        0x00,
                        LcsfAttDesc {
                            is_optional: false,
                            data_type: LcsfDataType::Uint8,
                            subatt_desc_arr: Vec::new(),
                        }
                    ),
                    (
                        0x01,
                        LcsfAttDesc {
                            is_optional: false,
                            data_type: LcsfDataType::Uint8,
                            subatt_desc_arr: Vec::new(),
                        }
                    ),
                ]
            }
        ),]
    };
}

// Lcsf ep constants
const LCSF_EP_ERR_CMD_ID: u16 = 0x0000;
const LCSF_EP_LOC_ATT_ID: u16 = 0x0000;
const LCSF_EP_TYPE_ATT_ID: u16 = 0x0001;
const LCSF_EP_ERR_CMD_ATT_NB: u16 = 2;

/// Encode a lcsf error message into a buffer
/// \param lcsf_mode encoding mode value
/// \param errorLoc location of the error encountered
/// \param errorType type of the error encountered
pub fn encode_error(lcsf_mode: LcsfModeEnum, error_loc: LcsfEpLocEnum, error_type: u8) -> Vec<u8> {
    // Init protocol id
    let mut prot_id: u16 = LCSF_EP_PROT_ID_NORMAL;
    if lcsf_mode == LcsfModeEnum::Small {
        prot_id = LCSF_EP_PROT_ID_SMALL;
    }
    // Create raw message
    let error_msg = LcsfRawMsg {
        prot_id: prot_id,
        cmd_id: LCSF_EP_ERR_CMD_ID,
        att_nb: LCSF_EP_ERR_CMD_ATT_NB,
        att_arr: vec![
            (
                LCSF_EP_LOC_ATT_ID,
                LcsfRawAtt {
                    has_subatt: false,
                    payload_size: 1,
                    payload: LcsfRawAttPayload::Data(vec![error_loc as u8]),
                },
            ),
            (
                LCSF_EP_TYPE_ATT_ID,
                LcsfRawAtt {
                    has_subatt: false,
                    payload_size: 1,
                    payload: LcsfRawAttPayload::Data(vec![error_type]),
                },
            ),
        ],
    };
    // Encode the message with encoder
    return lcsf_transcoder::encode_buff(lcsf_mode, &error_msg);
}

/// Process a lcsf error message
/// \param valid_cmd validated error message reference
pub fn process_error(valid_cmd: &LcsfValidCmd) -> (&str, &str) {
    let mut err_loc = 0;
    let mut err_type = 0;
    // Retrieve error information
    if let LcsfValidAttPayload::Data(data) = &valid_cmd.att_arr[LCSF_EP_LOC_ATT_ID as usize].payload
    {
        err_loc = data[0];
    };
    if let LcsfValidAttPayload::Data(data) =
        &valid_cmd.att_arr[LCSF_EP_TYPE_ATT_ID as usize].payload
    {
        err_type = data[0];
    };
    // Turn enum into string
    let loc_str: &str;
    let type_str: &str;
    match err_loc {
        0 => {
            loc_str = "Decoder";
            type_str = match err_type {
                0 => "Bad format",
                1 => "Overflow",
                _ => "Unknown",
            };
        }
        1 => {
            loc_str = "Validator";
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
        _ => {
            loc_str = "Unknown";
            type_str = "Unknown";
        }
    };
    return (loc_str, type_str);
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    use lcsf_transcoder::LcsfDecodeErrorEnum;
    use lcsf_validator::LcsfValidAtt;
    use lcsf_validator::LcsfValidateErrorEnum;

    #[test]
    pub fn test_encode_error() {
        // Test data
        let buff_small: Vec<u8> = vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x05];
        let buff_normal: Vec<u8> = vec![
            0xff, 0xff, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00,
        ];
        assert_eq!(
            buff_small,
            encode_error(
                LcsfModeEnum::Small,
                LcsfEpLocEnum::ValidationError,
                LcsfValidateErrorEnum::WrongAttDataType as u8
            )
        );
        assert_eq!(
            buff_normal,
            encode_error(
                LcsfModeEnum::Normal,
                LcsfEpLocEnum::DecodeError,
                LcsfDecodeErrorEnum::FormatErr as u8
            )
        );
    }

    #[test]
    pub fn test_process_error() {
        let mut valid_cmd = LcsfValidCmd {
            cmd_id: LCSF_EP_ERR_CMD_ID,
            att_arr: vec![
                LcsfValidAtt {
                    payload: LcsfValidAttPayload::Data(vec![0x00]),
                },
                LcsfValidAtt {
                    payload: LcsfValidAttPayload::Data(vec![0x01]),
                },
            ],
        };
        let (mut loc_str, mut type_str) = process_error(&valid_cmd);
        assert_eq!(loc_str, "Decoder");
        assert_eq!(type_str, "Overflow");

        valid_cmd = LcsfValidCmd {
            cmd_id: LCSF_EP_ERR_CMD_ID,
            att_arr: vec![
                LcsfValidAtt {
                    payload: LcsfValidAttPayload::Data(vec![0x01]),
                },
                LcsfValidAtt {
                    payload: LcsfValidAttPayload::Data(vec![0x04]),
                },
            ],
        };
        (loc_str, type_str) = process_error(&valid_cmd);
        assert_eq!(loc_str, "Validator");
        assert_eq!(type_str, "Missing mandatory attribute");
    }
}
