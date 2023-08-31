// Import
mod lcsf_transcoder;
mod lcsf_validator;
use lcsf_transcoder::LcsfModeEnum;
use lcsf_transcoder::LcsfRawMsg;
use lcsf_transcoder::LcsfRawAtt;
use lcsf_transcoder::LcsfRawAttPayload;

const BASIC_MSG:&'static [u8] = &[0xab, 0x12, 0x01, 0x55, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];

// Main
fn main() {
    let basic_msg = LcsfRawMsg {
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

    let msg = lcsf_transcoder::decode_buff(LcsfModeEnum::Small, BASIC_MSG);
    println!("Test: {msg:?}");
    let buff = lcsf_transcoder::encode_buff(LcsfModeEnum::Normal, &basic_msg);
    println!("Test2: {buff:?}");
}