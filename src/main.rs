// Import
mod lcsf_transcoder;
mod lcsf_validator;
mod lcsf_error;

use lcsf_transcoder::LcsfModeEnum;
use lcsf_transcoder::LcsfRawMsg;
use lcsf_transcoder::LcsfRawAtt;
use lcsf_transcoder::LcsfRawAttPayload;

use lcsf_validator::LcsfProtDesc;
use lcsf_validator::LcsfCmdDesc;
use lcsf_validator::LcsfAttDesc;
use lcsf_validator::LcsfDataType;
use lcsf_validator::LcsfValidCmd;
use lcsf_validator::LcsfValidAtt;
use lcsf_validator::LcsfValidAttPayload;
use lcsf_validator::LcsfValidateErrorEnum;

use lcsf_error::LcsfEpLocEnum;

const BASIC_MSG:&'static [u8] = &[0xab, 0x12, 0x01, 0x55, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];

fn dummy_process(cmd: &LcsfValidCmd){
    if let LcsfValidAttPayload::Data(data) = &cmd.att_arr[0].payload {
        println!("Command received:, id: {}, data: {:?}", cmd.cmd_id, data);
    };
}

fn dispatch_valid_cmd(prot_id: u16, valid_cmd: &LcsfValidCmd) {
    match prot_id {
        lcsf_error::LCSF_EP_PROT_ID_SMALL => lcsf_error::process_error(valid_cmd),
        lcsf_error::LCSF_EP_PROT_ID_NORMAL => lcsf_error::process_error(valid_cmd),
        0xab => dummy_process(valid_cmd),
        _ => {},
    }
}

// Main
fn main() {
    let basic_raw_msg = LcsfRawMsg {
        prot_id: 0xab,
        cmd_id: 0x12,
        att_nb: 1,
        att_arr: vec![
            (0x55, LcsfRawAtt {
                has_subatt: false,
                payload_size: 5,
                payload: LcsfRawAttPayload::Data(vec![0x00, 0x01, 0x02, 0x03, 0x04])
            }),
        ],
    };
    let basic_desc = LcsfProtDesc {
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
    let basic_valid_cmd = LcsfValidCmd {
        cmd_id: 0x12,
        att_arr: vec![
            LcsfValidAtt {
                payload: LcsfValidAttPayload::Data(vec![0x00, 0x01, 0x02, 0x03, 0x04]),
            },
        ]
    };
    let err_valid_cmd = LcsfValidCmd {
        cmd_id: 0x00,
        att_arr: vec![
            LcsfValidAtt {
                payload: LcsfValidAttPayload::Data(vec![0x00]),
            },
            LcsfValidAtt {
                payload: LcsfValidAttPayload::Data(vec![0x01]),
            },
        ]
    };
    let prot_desc_arr:Vec<(u16, &LcsfProtDesc)> = vec![
        (lcsf_error::LCSF_EP_PROT_ID_SMALL, &lcsf_error::LCSF_EP_PROT_DESC), (0xab, &basic_desc),
    ];

    // Transcoder
    let raw_msg = match lcsf_transcoder::decode_buff(LcsfModeEnum::Small, BASIC_MSG) {
        Err(err) => panic!("decode_buff failed with err {err:?} but should not fail"),
        Ok(msg) => msg,
    };
    println!("Test decode: {raw_msg:?}");
    let buff = lcsf_transcoder::encode_buff(LcsfModeEnum::Normal, &basic_raw_msg);
    println!("Test encode: {buff:?}");
    // Validator
    let (valid_msg, prot_id) = match lcsf_validator::validate_msg(&prot_desc_arr, &basic_raw_msg) {
        Err(err) => panic!("validate_msg failed with err {err:?} but should not fail"),
        Ok((msg, id)) => (msg, id),
    };
    println!("Test validate: {valid_msg:?}");
    dispatch_valid_cmd(prot_id, &valid_msg);
    let raw_msg = lcsf_validator::encode_valid(0xab, &basic_desc.cmd_desc_arr[0].1, &basic_valid_cmd).unwrap();
    println!("Test encode valid: {raw_msg:?}");
    // Error
    let buff = lcsf_error::encode_error(LcsfModeEnum::Normal, LcsfEpLocEnum::ValidationError, LcsfValidateErrorEnum::UnknownAttId as u8);
    println!("Test encode error: {buff:?}");
    lcsf_error::process_error(&err_valid_cmd);
}