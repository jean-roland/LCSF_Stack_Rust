/// author: Jean-Roland Gosse
/// desc: Light Command Set Format validator module
///
/// This file is part of LCSF Stack Rust.
/// You should have received a copy of the GNU Lesser General Public License
/// along with this program. If not, see <https://www.gnu.org/licenses/>

use core::mem::size_of;
use std::collections::HashMap;

use crate::lcsf_transcoder;
use lcsf_transcoder::LcsfRawMsg;
use lcsf_transcoder::LcsfRawAtt;
use lcsf_transcoder::LcsfRawAttPayload;

// *** Types ***

// Data type enum
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum LcsfDataType {
    Uint8,
    Uint16,
    Uint32,
    ByteArray,
    String,
    Subattributes,
}

// Lcsf attribute descriptor structure
#[derive(Debug, PartialEq, Clone)]
pub struct LcsfAttDesc {
    pub is_optional:bool, // Indicates if is optional
    pub data_type:LcsfDataType,
    pub subatt_desc_arr:Vec<(u16, LcsfAttDesc)>,
}

// Lcsf command descriptor structure
#[derive(Debug, PartialEq, Clone)]
pub struct LcsfCmdDesc {
    pub att_desc_arr:Vec<(u16, LcsfAttDesc)>,
}

// Lcsf protocol descriptor structure */
#[derive(Debug, PartialEq)]
pub struct LcsfProtDesc {
    pub cmd_desc_arr:Vec<(u16, LcsfCmdDesc)>,
}

// Lcsf valid attribute payload union
#[derive(Debug, PartialEq, Clone)]
pub enum LcsfValidAttPayload {
    Data(Vec<u8>),
    SubattArr(Vec<LcsfValidAtt>),
}

// Lcsf valid attribute structure
#[derive(Debug, PartialEq, Clone)]
pub struct LcsfValidAtt {
    pub payload:LcsfValidAttPayload,
}

// Lcsf valid command structure
#[derive(Debug, PartialEq, Clone)]
pub struct LcsfValidCmd {
    pub cmd_id:u16,
    pub att_arr:Vec<LcsfValidAtt>,
}

/// Lcsf decoding error enum
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum LcsfValidateErrorEnum {
    UnknownProtId = 0x00,
    UnknownCmdId = 0x01,
    UnknownAttId = 0x02,
    TooManyAtt = 0x03,
    MissMandatoryAtt = 0x04,
    WrongAttDataType = 0x05,
}

/// Validate the data size of received attribute payload
/// \param data_size size of the data
/// \param data_type type of the data
fn validate_data_type(data_size:usize, data_type:LcsfDataType) -> bool {
    // Check data type
    match data_type {
        LcsfDataType::Uint8 => return data_size == size_of::<u8>(),
        LcsfDataType::Uint16 => return data_size == size_of::<u16>(),
        LcsfDataType::Uint32 => return data_size == size_of::<u32>(),
        LcsfDataType::ByteArray => return data_size > 0,
        LcsfDataType::String => return data_size > 0,
        _ => return false,
    }
}

/// Recursively validate received attributes and their payload
/// \param att_id attribute id value
/// \param att_desc attribute descriptor reference
/// \param rx_att_arr received (id, attribute) array reference
fn validate_att_rec(att_id:u16, att_desc:&LcsfAttDesc, rx_att_arr:&[(u16, LcsfRawAtt)]) -> Result<(usize, LcsfValidAtt), LcsfValidateErrorEnum> {
    let mut valid_att = LcsfValidAtt {
        payload: LcsfValidAttPayload::Data(Vec::new()),
    };
    let mut local_payload_size:usize = 0; // To avoid de-structuring to get vec.len()

    // Check for attribute in received array
    let rx_att_map: HashMap<u16, LcsfRawAtt> = rx_att_arr.iter().cloned().collect();
    let rx_att = match rx_att_map.get(&att_id) {
        None => {
            // Attribute missing, check optional
            if !att_desc.is_optional {
                return Err(LcsfValidateErrorEnum::MissMandatoryAtt);
            } else {
                return Ok((local_payload_size, valid_att));
            }
        },
        Some(att) => att,
    };
    // Attribute present, check payload type
    if att_desc.data_type == LcsfDataType::Subattributes {
        // Check data type
        if !rx_att.has_subatt {
            return Err(LcsfValidateErrorEnum::WrongAttDataType);
        }
        // Payload de-structuring
        if let LcsfRawAttPayload::SubattArr(rx_subatt_arr) = &rx_att.payload {
            valid_att.payload = LcsfValidAttPayload::SubattArr(Vec::new());
            let mut subatt_count:usize = 0;

            // Too many attributes case
            if rx_subatt_arr.len() > att_desc.subatt_desc_arr.len() {
                return Err(LcsfValidateErrorEnum::TooManyAtt);
            }
            // Parse through the sub-descriptor list
            for (sub_id, sub_desc) in &att_desc.subatt_desc_arr {
                // Process attribute
                let (sub_payload_size, valid_subatt) = validate_att_rec(*sub_id, sub_desc, rx_subatt_arr)?;
                // Count sub-attribute presence
                if sub_payload_size > 0 {
                    subatt_count += 1;
                }
                // Add sub-attribute to array
                if let LcsfValidAttPayload::SubattArr(valid_subatt_arr) = &mut valid_att.payload {
                    valid_subatt_arr.push(valid_subatt);
                    local_payload_size += 1;
                };
            }
            // Unrecognized attribute case
            if subatt_count < rx_subatt_arr.len() {
                return Err(LcsfValidateErrorEnum::UnknownAttId);
            }
        };
    } else {
        // Check data type
        if !validate_data_type(rx_att.payload_size as usize, att_desc.data_type) {
            return Err(LcsfValidateErrorEnum::WrongAttDataType);
        }
        // Note data and data size
        if let LcsfRawAttPayload::Data(rx_data) = &rx_att.payload {
            if let LcsfValidAttPayload::Data(valid_data) = &mut valid_att.payload {
                *valid_data = rx_data.clone();
                local_payload_size = rx_data.len();
            }
        };
    }
    return Ok((local_payload_size, valid_att));
}

#[test]
fn test_validate_att_rec() {
    let bad_att1 = vec![(0x40, LcsfRawAtt {
        has_subatt: false,
        payload_size: 1,
        payload: LcsfRawAttPayload::Data(vec![0x00])
    })];
    let mut bad_att2 = vec![(0x31, LcsfRawAtt {
        has_subatt: false,
        payload_size: 2,
        payload: LcsfRawAttPayload::SubattArr(vec![
            (0x55, LcsfRawAtt {
                has_subatt: false,
                payload_size: 1,
                payload: LcsfRawAttPayload::Data(vec![0x00])
            }),
            (0x55, LcsfRawAtt {
                has_subatt: false,
                payload_size: 1,
                payload: LcsfRawAttPayload::Data(vec![0x00])
            }),
        ]),
    })];
    let att_desc_arr = &TEST_PROT_DESC.cmd_desc_arr[0].1.att_desc_arr;

    // Test error
    match validate_att_rec(0x55, &att_desc_arr[0].1, &bad_att1) {
        Ok(_) => panic!("validate_att_rec should have failed"),
        Err(err) => assert_eq!(err, LcsfValidateErrorEnum::MissMandatoryAtt),
    }
    match validate_att_rec(0x40, &att_desc_arr[2].1, &bad_att1) {
        Ok(_) => panic!("validate_att_rec should have failed"),
        Err(err) => assert_eq!(err, LcsfValidateErrorEnum::WrongAttDataType),
    }
    match validate_att_rec(0x31, &att_desc_arr[1].1.subatt_desc_arr[1].1, &bad_att2) {
        Ok(_) => panic!("validate_att_rec should have failed"),
        Err(err) => assert_eq!(err, LcsfValidateErrorEnum::WrongAttDataType),
    }
    bad_att2[0].1.has_subatt = true;
    match validate_att_rec(0x31, &att_desc_arr[1].1.subatt_desc_arr[1].1, &bad_att2) {
        Ok(_) => panic!("validate_att_rec should have failed"),
        Err(err) => assert_eq!(err, LcsfValidateErrorEnum::TooManyAtt),
    }
    if let LcsfRawAttPayload::SubattArr(subatt_arr) = &mut bad_att2[0].1.payload {
        subatt_arr.remove(1);
    };
    match validate_att_rec(0x31, &att_desc_arr[1].1.subatt_desc_arr[1].1, &bad_att2) {
        Ok(_) => panic!("validate_att_rec should have failed"),
        Err(err) => assert_eq!(err, LcsfValidateErrorEnum::UnknownAttId),
    }
    // Test valid
    for (idx, (att_id, att_desc)) in att_desc_arr.iter().enumerate() {
        match validate_att_rec(*att_id, att_desc, &TEST_RAW_MSG.att_arr) {
            Err(err) => panic!("decode_att_rec failed with error: {err:?}, but should not fail"),
            Ok((_, valid_att)) => assert_eq!(valid_att, TEST_VALID_CMD.att_arr[idx]),
        };
    }
}

/// Validate a received lcsf raw message
/// \param desc_arr (protocol id, protocol descriptor) array reference
/// \param rx_msg received message reference
pub fn validate_msg(prot_desc_arr:&Vec<(u16, &LcsfProtDesc)>, rx_msg:&LcsfRawMsg)
    -> Result<(LcsfValidCmd, u16), LcsfValidateErrorEnum> {
    let mut valid_cmd = LcsfValidCmd {
        cmd_id: 0,
        att_arr: Vec::new(),
    };
    // Check protocol id valid
    let prot_desc_map:HashMap<u16, &LcsfProtDesc> = prot_desc_arr.iter().cloned().collect();
    let prot_desc = match prot_desc_map.get(&rx_msg.prot_id) {
        None => return Err(LcsfValidateErrorEnum::UnknownProtId),
        Some(desc) => desc,
    };
    // Check command id valid
    let cmd_desc_map:HashMap<u16, LcsfCmdDesc> = prot_desc.cmd_desc_arr.iter().cloned().collect();
    let cmd_desc = match cmd_desc_map.get(&rx_msg.cmd_id) {
        None => return Err(LcsfValidateErrorEnum::UnknownCmdId),
        Some(desc) => desc,
    };
    // Note data
    valid_cmd.cmd_id = rx_msg.cmd_id;
    // Check rx attributes array length
    if rx_msg.att_arr.len() > cmd_desc.att_desc_arr.len() {
        return Err(LcsfValidateErrorEnum::TooManyAtt);
    }
    // Validate attributes
    for (att_id, att_desc) in &cmd_desc.att_desc_arr {
        let (_, valid_att) = validate_att_rec(*att_id, att_desc, &rx_msg.att_arr)?;
        valid_cmd.att_arr.push(valid_att);
    }
    return Ok((valid_cmd, rx_msg.prot_id));
}

#[test]
fn test_validate_msg() {
    // Test data
    let prot_desc_arr:Vec<(u16, &LcsfProtDesc)> = vec![(0xab, &TEST_PROT_DESC)];
    let mut bad_msg = LcsfRawMsg {
        prot_id: 0,
        cmd_id: 0,
        att_nb: 4,
        att_arr: vec![
            (0x01, LcsfRawAtt {
                has_subatt: false,
                payload_size: 0,
                payload: LcsfRawAttPayload::Data(Vec::new()),
            }),
            (0x02, LcsfRawAtt {
                has_subatt: false,
                payload_size: 0,
                payload: LcsfRawAttPayload::Data(Vec::new()),
            }),
            (0x03, LcsfRawAtt {
                has_subatt: false,
                payload_size: 0,
                payload: LcsfRawAttPayload::Data(Vec::new()),
            }),
            (0x04, LcsfRawAtt {
                has_subatt: false,
                payload_size: 0,
                payload: LcsfRawAttPayload::Data(Vec::new()),
            }),
        ],
    };
    // Test error
    match validate_msg(&prot_desc_arr, &bad_msg) {
        Ok(_) => panic!("validate_msg should fail"),
        Err(err) => assert_eq!(err, LcsfValidateErrorEnum::UnknownProtId),
    }
    bad_msg.prot_id = 0xab;
    match validate_msg(&prot_desc_arr, &bad_msg) {
        Ok(_) => panic!("validate_msg should fail"),
        Err(err) => assert_eq!(err, LcsfValidateErrorEnum::UnknownCmdId),
    }
    bad_msg.cmd_id = 0x12;
    match validate_msg(&prot_desc_arr, &bad_msg) {
        Ok(_) => panic!("validate_msg should fail"),
        Err(err) => assert_eq!(err, LcsfValidateErrorEnum::TooManyAtt),
    }
    // Test valid
    match validate_msg(&prot_desc_arr, &TEST_RAW_MSG) {
        Err(err) => panic!("decode_att_rec failed with error: {err:?}, but should not fail"),
        Ok((valid_cmd, id)) => {
            assert_eq!(valid_cmd, *TEST_VALID_CMD);
            assert_eq!(id, 0xab);
        },
    }
}

/// Fill a raw attribute info from a valid attribute
/// \param data_type attribute data type from descriptor
/// \param valid_att valid attribute reference
fn fill_att_info(data_type:LcsfDataType, valid_att:&LcsfValidAtt) -> Option<LcsfRawAtt> {
    let mut raw_att = LcsfRawAtt {
        has_subatt: false,
        payload_size: 0,
        payload: LcsfRawAttPayload::Data(Vec::new()),
    };
    // Check sub-attribute type
    if data_type == LcsfDataType::Subattributes {
        if let LcsfValidAttPayload::SubattArr(subatt_arr) = &valid_att.payload {
            if subatt_arr.len() == 0 {
                return None;
            }
            // Note data
            raw_att.has_subatt = true;
            raw_att.payload_size = subatt_arr.len() as u16;
            raw_att.payload = LcsfRawAttPayload::SubattArr(Vec::new());
        };
    } else {
        // Check other data types
        if let LcsfValidAttPayload::Data(data) = &valid_att.payload {
            match data_type {
                LcsfDataType::Uint8 => {
                    if data.len() != std::mem::size_of::<u8>() {
                        return None;
                    }
                },
                LcsfDataType::Uint16 => {
                    if data.len() != std::mem::size_of::<u16>() {
                        return None;
                    }
                },
                LcsfDataType::Uint32 => {
                    if data.len() != std::mem::size_of::<u32>() {
                        return None;
                    }
                },
                LcsfDataType::ByteArray => {
                    if data.len() == 0 {
                        return None;
                    }
                },
                LcsfDataType::String => {
                    if data.len() == 0 {
                        return None;
                    }
                },
                _ => return None,
            }
            // Note data
            raw_att.payload_size = data.len() as u16;
            raw_att.payload = LcsfRawAttPayload::Data(data.clone());
        };
    }
    return Some(raw_att);
}

#[test]
fn test_fill_att_info() {
    // Test data
    let valid_att_u8 = LcsfValidAtt {
        payload: LcsfValidAttPayload::Data(vec![0x0a]),
    };
    let raw_att_u8 = LcsfRawAtt {
        has_subatt: false,
        payload_size: 1,
        payload: LcsfRawAttPayload::Data(vec![0x0a]),
    };
    let valid_att_u16 = LcsfValidAtt {
        payload: LcsfValidAttPayload::Data(vec![0x55, 0xaa]),
    };
    let raw_att_u16 = LcsfRawAtt {
        has_subatt: false,
        payload_size: 2,
        payload: LcsfRawAttPayload::Data(vec![0x55, 0xaa]),
    };
    let valid_att_u32 = LcsfValidAtt {
        payload: LcsfValidAttPayload::Data(vec![0x1a, 0x2b, 0x3c, 0x4d]),
    };
    let raw_att_u32 = LcsfRawAtt {
        has_subatt: false,
        payload_size: 4,
        payload: LcsfRawAttPayload::Data(vec![0x1a, 0x2b, 0x3c, 0x4d]),
    };
    let valid_att_arr = LcsfValidAtt {
        payload: LcsfValidAttPayload::Data(vec![0x10, 0x20, 0x30, 0x40, 0x00]),
    };
    let raw_att_arr = LcsfRawAtt {
        has_subatt: false,
        payload_size: 5,
        payload: LcsfRawAttPayload::Data(vec![0x10, 0x20, 0x30, 0x40, 0x00]),
    };
    let valid_att_sub = LcsfValidAtt {
        payload: LcsfValidAttPayload::SubattArr(vec![
            LcsfValidAtt {
               payload: LcsfValidAttPayload::Data(vec![0xff]),
            },
        ]),
    };
    let raw_att_sub = LcsfRawAtt {
        has_subatt: true,
        payload_size: 1,
        payload: LcsfRawAttPayload::SubattArr(Vec::new()),
    };
    let mut valid_att_err = LcsfValidAtt {
        payload: LcsfValidAttPayload::SubattArr(Vec::new()),
    };
    // Test error
    match fill_att_info(LcsfDataType::Subattributes, &valid_att_err) {
        Some(_) => panic!("fill_att_info should fail"),
        None => {},
    }
    valid_att_err.payload = LcsfValidAttPayload::Data(Vec::new());
    match fill_att_info(LcsfDataType::Uint32, &valid_att_err) {
        Some(_) => panic!("fill_att_info should fail"),
        None => {},
    }
    // Test valid
    match fill_att_info(LcsfDataType::Uint8, &valid_att_u8) {
        None => panic!("fill_att_info should not fail"),
        Some(raw_att) => assert_eq!(raw_att, raw_att_u8),
    }
    match fill_att_info(LcsfDataType::Uint16, &valid_att_u16) {
        None => panic!("fill_att_info should not fail"),
        Some(raw_att) => assert_eq!(raw_att, raw_att_u16),
    }
    match fill_att_info(LcsfDataType::Uint32, &valid_att_u32) {
        None => panic!("fill_att_info should not fail"),
        Some(raw_att) => assert_eq!(raw_att, raw_att_u32),
    }
    match fill_att_info(LcsfDataType::ByteArray, &valid_att_arr) {
        None => panic!("fill_att_info should not fail"),
        Some(raw_att) => assert_eq!(raw_att, raw_att_arr),
    }
    match fill_att_info(LcsfDataType::String, &valid_att_arr) {
        None => panic!("fill_att_info should not fail"),
        Some(raw_att) => assert_eq!(raw_att, raw_att_arr),
    }
    match fill_att_info(LcsfDataType::Subattributes, &valid_att_sub) {
        None => panic!("fill_att_info should not fail"),
        Some(raw_att) => assert_eq!(raw_att, raw_att_sub),
    }
}

/// Fill recursively a raw attribute from a valid attribute following a descriptor
/// \param att_desc attribute descriptor reference
/// \param valid_att valid attribute reference
fn fill_att_rec(att_desc:&LcsfAttDesc, valid_att:&LcsfValidAtt) -> Option<LcsfRawAtt> {
    // Init raw_att
    let mut raw_att = LcsfRawAtt {
        has_subatt: false,
        payload_size: 0,
        payload: LcsfRawAttPayload::Data(Vec::new()),
    };
    // Split data and sub-attribute cases
    if att_desc.data_type == LcsfDataType::Subattributes {
        if let LcsfValidAttPayload::SubattArr(valid_subatt_arr) = &valid_att.payload {
            // Check sub-attribute number
            if valid_subatt_arr.len() != att_desc.subatt_desc_arr.len() {
                return None;
            }
            // Check missing attribute
            if valid_subatt_arr.len() == 0 {
                // Check if mandatory
                if !att_desc.is_optional {
                    return None;
                } else {
                    return Some(raw_att);
                }
            }
            // Fill raw att header
            raw_att = fill_att_info(att_desc.data_type, &valid_att)?;
            // Parse valid sub-attribute array
            for (idx, valid_subatt) in valid_subatt_arr.iter().enumerate() {
                // Get sub-attribute description
                let (subatt_id, subatt_desc) = att_desc.subatt_desc_arr.get(idx)?;
                // Store raw sub-attribute
                if let LcsfRawAttPayload::SubattArr(raw_subat_arr) = &mut raw_att.payload {
                    raw_subat_arr.push((*subatt_id, fill_att_rec(subatt_desc, valid_subatt)?));
                };
            }
        };
    } else {
        if let LcsfValidAttPayload::Data(data) = &valid_att.payload {
            // Check missing attribute
            if data.len() == 0 {
                // Check if mandatory
                if !att_desc.is_optional {
                    return None;
                } else {
                    return Some(raw_att);
                }
            }
            // Fill raw att
            raw_att = fill_att_info(att_desc.data_type, &valid_att)?;
        }
    }
    return Some(raw_att);
}

#[test]
fn test_fill_att_rec() {
    // Test data
    let mut test_att_desc = LcsfAttDesc {
        is_optional: false,
        data_type: LcsfDataType::Subattributes,
        subatt_desc_arr: Vec::new(),
    };
    let empty_valid_att = LcsfValidAtt {
        payload: LcsfValidAttPayload::SubattArr(Vec::new()),
    };
    let empty_raw_att = LcsfRawAtt {
        has_subatt: false,
        payload_size: 0,
        payload: LcsfRawAttPayload::Data(Vec::new()),
    };
    // Test error
    match fill_att_rec(&test_att_desc, &empty_valid_att) {
        Some(_) => panic!("fill_att_rec should fail"),
        None => {},
    }
    // Test valid
    test_att_desc.is_optional = true;
    match fill_att_rec(&test_att_desc, &empty_valid_att) {
        Some(raw_att) => assert_eq!(raw_att, empty_raw_att),
        None => panic!("fill_att_rec should not fail"),
    }
    for (idx, valid_att) in TEST_VALID_CMD.att_arr.iter().enumerate() {
        let att_desc = &TEST_PROT_DESC.cmd_desc_arr[0].1.att_desc_arr[idx].1;
        match fill_att_rec(att_desc, valid_att) {
            None => panic!("fill_att_rec should not fail"),
            Some(raw_att) => assert_eq!(raw_att, TEST_RAW_MSG.att_arr[idx].1),
        }
    }
}

/// Encode a valid command and its descriptor into a lcsf raw message
/// \param prot_id protocol id
/// \param cmd_desc command descriptor reference
/// \param valid_cmd valid command reference
pub fn encode_valid(prot_id:u16, cmd_desc:&LcsfCmdDesc, valid_cmd:&LcsfValidCmd) -> Option<LcsfRawMsg> {
    // Init raw message
    let mut raw_msg = LcsfRawMsg {
        prot_id: prot_id,
        cmd_id: valid_cmd.cmd_id,
        att_nb: valid_cmd.att_arr.len() as u16,
        att_arr: Vec::new(),
    };
    // Check attribute number
    if valid_cmd.att_arr.len() != cmd_desc.att_desc_arr.len() {
        return None;
    }
    // Fill attribute array
    for (idx, valid_att) in valid_cmd.att_arr.iter().enumerate() {
        let (att_id, att_desc) = cmd_desc.att_desc_arr.get(idx)?;
        raw_msg.att_arr.push((*att_id, fill_att_rec(att_desc, valid_att)?));
    }
    return Some(raw_msg);
}

#[test]
pub fn test_encode_valid() {
    // Test data
    let bad_cmd = LcsfValidCmd {
        cmd_id: 0x12,
        att_arr: Vec::new(),
    };
    // Test error
    match encode_valid(0xab, &TEST_PROT_DESC.cmd_desc_arr[0].1, &bad_cmd) {
        Some(_) => panic!("fill_att_rec should fail"),
        None => {},
    }
    // Test valid
    match encode_valid(0xab, &TEST_PROT_DESC.cmd_desc_arr[0].1, &TEST_VALID_CMD) {
        None => panic!("encode_valid should not fail"),
        Some(raw_msg) => assert_eq!(raw_msg, *TEST_RAW_MSG),
    }
}



#[cfg(test)]
use lazy_static::lazy_static;
#[cfg(test)]
use lcsf_transcoder::TEST_RAW_MSG;

#[cfg(test)]
lazy_static! {
    static ref TEST_PROT_DESC:LcsfProtDesc = LcsfProtDesc {
        cmd_desc_arr: vec![
            (0x12, LcsfCmdDesc {
                att_desc_arr: vec![
                    (0x55, LcsfAttDesc {
                        is_optional: false,
                        data_type: LcsfDataType::ByteArray,
                        subatt_desc_arr: Vec::new(),
                    }),
                    (0x7f, LcsfAttDesc {
                        is_optional: false,
                        data_type: LcsfDataType::Subattributes,
                        subatt_desc_arr: vec![
                            (0x30, LcsfAttDesc {
                                is_optional: false,
                                data_type: LcsfDataType::Uint8,
                                subatt_desc_arr: Vec::new(),
                            }),
                            (0x31, LcsfAttDesc {
                                is_optional: false,
                                data_type: LcsfDataType::Subattributes,
                                subatt_desc_arr: vec![
                                    (0x32, LcsfAttDesc {
                                        is_optional: true,
                                        data_type: LcsfDataType::String,
                                        subatt_desc_arr: Vec::new(),
                                    }),
                                ],
                            }),
                        ],
                    }),
                    (0x40, LcsfAttDesc {
                        is_optional: true,
                        data_type: LcsfDataType::Uint16,
                        subatt_desc_arr: Vec::new(),
                    }),
                ],
            }),
        ],
    };

    static ref TEST_VALID_CMD:LcsfValidCmd = LcsfValidCmd {
        cmd_id: 0x12,
        att_arr: vec![
            LcsfValidAtt {
                payload: LcsfValidAttPayload::Data(vec![0x00, 0x01, 0x02, 0x03, 0x04]),
            },
            LcsfValidAtt {
                payload: LcsfValidAttPayload::SubattArr(vec![
                    LcsfValidAtt {
                        payload: LcsfValidAttPayload::Data(vec![0xa]),
                    },
                    LcsfValidAtt {
                        payload: LcsfValidAttPayload::SubattArr(vec![
                            LcsfValidAtt {
                                payload: LcsfValidAttPayload::Data(vec![
                                    0x4f, 0x72, 0x67, 0x61, 0x6e, 0x6f, 0x6c,
                                    0x65, 0x70, 0x74, 0x69, 0x63, 0x00,
                                ]),
                            },
                        ])
                    },
                ])
            },
            LcsfValidAtt {
                payload: LcsfValidAttPayload::Data(vec![0xab, 0xcd]),
            },
        ],
    };
}