//! Serialize and de-serialize data buffer to and from LcsfRawMsg
//!
//! author: Jean-Roland Gosse
//!
//! This file is part of LCSF Stack Rust.
//! Spec details at <https://jean-roland.github.io/LCSF_Doc/>
//! You should have received a copy of the GNU Lesser General Public License
//! along with this program. If not, see <https://www.gnu.org/licenses/>

use core::slice::Iter;

/// Lcsf representation mode enum
#[allow(dead_code)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum LcsfModeEnum {
    /// Smaller size lcsf (1 byte / field)
    Small = 0,
    /// Regular size lcsf (2 bytes / field)
    Normal = 1,
}

/// Lcsf decoding error enum
#[allow(dead_code)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum LcsfDecodeErrorEnum {
    /// Message formatting error, missing or leftover data compared to what's expected
    FormatErr = 0x00,
    /// The message is too big or too complex to be processed by the module
    OverflowErr = 0x01,
}

/// Lcsf raw attribute payload union
#[derive(Debug, PartialEq, Clone)]
pub enum LcsfRawAttPayload {
    /// A vector of bytes containing the data
    Data(Vec<u8>),
    /// A vector containing the sub-attributes as (id, sub-attribute) tuple
    SubattArr(Vec<(u16, LcsfRawAtt)>),
}

/// Lcsf raw attribute structure
#[derive(Debug, PartialEq, Clone)]
pub struct LcsfRawAtt {
    /// Indicates if the attribute has sub attributes or data
    pub has_subatt: bool,
    /// Data size (bytes) or sub-attribute number
    pub payload_size: u16,
    /// See [LcsfRawAttPayload]
    pub payload: LcsfRawAttPayload,
}

/// Lcsf raw message structure
#[derive(Debug, PartialEq, Clone)]
pub struct LcsfRawMsg {
    /// Protocol id
    pub prot_id: u16,
    /// Command id
    pub cmd_id: u16,
    /// Number of attributes
    pub att_nb: u16,
    /// Vector of attributes as (id, attribute) tuple
    pub att_arr: Vec<(u16, LcsfRawAtt)>,
}

// *** Decoder ***

/// Fetch a lcsf message header struct from a buffer iterator
///
/// lcsf_mode: parsing mode to use, see [LcsfModeEnum]
///
/// buff_iter: buffer iterator reference
fn fetch_msg_header(lcsf_mode: LcsfModeEnum, buff_iter: &mut Iter<u8>) -> Option<LcsfRawMsg> {
    let mut msg = LcsfRawMsg {
        prot_id: 0,
        cmd_id: 0,
        att_nb: 0,
        att_arr: Vec::new(),
    };
    // Parse the message header based on the lcsf_mode
    if lcsf_mode == LcsfModeEnum::Small {
        // Byte 1: Protocol id
        msg.prot_id = *buff_iter.next()? as u16;
        // Byte 2: Command id
        msg.cmd_id = *buff_iter.next()? as u16;
        // Byte 3: Attribute number
        msg.att_nb = *buff_iter.next()? as u16;
    } else {
        // Byte 1: Protocol id LSB
        msg.prot_id = *buff_iter.next()? as u16;
        // Byte 2: Protocol id MSB
        msg.prot_id += (*buff_iter.next()? as u16) << 8;
        // Byte 3: Command id LSB
        msg.cmd_id = *buff_iter.next()? as u16;
        // Byte 4: Command id MSB
        msg.cmd_id += (*buff_iter.next()? as u16) << 8;
        // Byte 5: Attribute Number LSB
        msg.att_nb = *buff_iter.next()? as u16;
        // Byte 6: Attribute Number MSB
        msg.att_nb += (*buff_iter.next()? as u16) << 8;
    }
    Some(msg)
}

/// Fetch a lcsf attribute header struct from a buffer iterator
///
/// lcsf_mode: parsing mode to use, see [LcsfModeEnum]
///
/// buff_iter: buffer iterator reference
fn fetch_att_header(
    lcsf_mode: LcsfModeEnum,
    buff_iter: &mut Iter<u8>,
) -> Option<(u16, LcsfRawAtt)> {
    let mut att = LcsfRawAtt {
        has_subatt: false,
        payload_size: 0,
        payload: LcsfRawAttPayload::Data(Vec::new()),
    };
    let mut att_id: u16;
    // Parse the protocol id and command id based on the lcsf_mode
    if lcsf_mode == LcsfModeEnum::Small {
        // Byte 1: Attribute id + Sub-attribute flag (MSb)
        let byte1 = *buff_iter.next()? as u16;
        att.has_subatt = (byte1 & (1 << 7)) != 0; // Retrieve the flag
        att_id = byte1 & !(1 << 7); // Mask the flag from the id
                                    // Byte 2: Payload size
        att.payload_size = *buff_iter.next()? as u16;
    } else {
        // Byte 1: Attribute id LSB
        att_id = *buff_iter.next()? as u16;
        // Byte 2: Attribute id MSB + Sub-attribute flag (MSb)
        let byte2 = *buff_iter.next()? as u16;
        att.has_subatt = (byte2 & (1 << 7)) != 0; // Retrieve the flag
        att_id += (byte2 & !(1 << 7)) << 8; // Mask the flag from the id
                                            // Byte 3: Payload size LSB
        att.payload_size = *buff_iter.next()? as u16;
        // Byte 4: Payload size MSB
        att.payload_size += (*buff_iter.next()? as u16) << 8;
    }
    Some((att_id, att))
}

/// Decode recursively a lcsf attribute from a buffer iterator
///
/// lcsf_mode: parsing mode to use, see [LcsfModeEnum]
///
/// buff_iter: buffer iterator reference
fn decode_att_rec(
    lcsf_mode: LcsfModeEnum,
    buff_iter: &mut Iter<u8>,
) -> Result<(u16, LcsfRawAtt), LcsfDecodeErrorEnum> {
    // Decode current attribute header
    let (att_id, mut att) = match fetch_att_header(lcsf_mode, buff_iter) {
        None => return Err(LcsfDecodeErrorEnum::FormatErr),
        Some((att_id, att_header)) => (att_id, att_header),
    };
    // Test if attribute has data or sub-attributes
    if att.has_subatt {
        att.payload = LcsfRawAttPayload::SubattArr(Vec::new());
        // Parse through the attribute array
        for _att_idx in 0..att.payload_size {
            // Decode sub-attribute
            let (subatt_id, subatt) = decode_att_rec(lcsf_mode, buff_iter)?;
            // Add sub-attribute
            if let LcsfRawAttPayload::SubattArr(subatt_arr) = &mut att.payload {
                subatt_arr.push((subatt_id, subatt));
            };
        }
    } else {
        // Take the data from buff_iter
        let data: Vec<u8> = buff_iter.take(att.payload_size as usize).copied().collect();
        if data.len() != att.payload_size as usize {
            return Err(LcsfDecodeErrorEnum::FormatErr);
        }
        // Store data
        att.payload = LcsfRawAttPayload::Data(data);
    }
    Ok((att_id, att))
}

/// Decode a buffer into a LcsfRawMsg
///
/// lcsf_mode: parsing mode to use, see [LcsfModeEnum]
///
/// buffer: data buffer reference
pub fn decode_buff(
    lcsf_mode: LcsfModeEnum,
    buffer: &[u8],
) -> Result<LcsfRawMsg, LcsfDecodeErrorEnum> {
    let mut dec_msg: LcsfRawMsg;
    let buff_iter = &mut buffer.iter();

    // Decode message header
    match fetch_msg_header(lcsf_mode, buff_iter) {
        None => return Err(LcsfDecodeErrorEnum::FormatErr),
        Some(msg) => dec_msg = msg, // Store message
    };
    // Decode attribute array
    for _idx in 0..dec_msg.att_nb {
        let (new_id, new_att) = decode_att_rec(lcsf_mode, buff_iter)?;
        // Store attribute
        dec_msg.att_arr.push((new_id, new_att));
    }
    // Unused leftover data
    if buff_iter.next().is_some() {
        return Err(LcsfDecodeErrorEnum::FormatErr);
    }
    Ok(dec_msg)
}

// *** Encoder ***

/// Encode a lcsf message header into a buffer
///
/// lcsf_mode: parsing mode to use, see [LcsfModeEnum]
///
/// msg: lcsf message header reference
fn fill_msg_header(lcsf_mode: LcsfModeEnum, msg: &LcsfRawMsg) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();

    if lcsf_mode == LcsfModeEnum::Small {
        // Byte 1: Protocol id
        buffer.push(msg.prot_id as u8);
        // Byte 2: Command id
        buffer.push(msg.cmd_id as u8);
        // Byte 3: Attribute number
        buffer.push(msg.att_nb as u8);
    } else {
        // Byte 1: Protocol id LSB
        buffer.push(msg.prot_id as u8);
        // Byte 2: Protocol id MSB
        buffer.push((msg.prot_id >> 8) as u8);
        // Byte 3: Command id LSB
        buffer.push(msg.cmd_id as u8);
        // Byte 4: Command id MSB
        buffer.push((msg.cmd_id >> 8) as u8);
        // Byte 5: Attribute number LSB
        buffer.push(msg.att_nb as u8);
        // Byte 6: Attribute number MSB
        buffer.push((msg.att_nb >> 8) as u8);
    }
    buffer
}

/// Encode a lcsf attribute header into a buffer
///
/// lcsf_mode: parsing mode to use, see [LcsfModeEnum]
///
/// att_id: attribute id value
///
/// att: attribute header to encode reference
fn fill_att_header(lcsf_mode: LcsfModeEnum, att_id: u16, att: &LcsfRawAtt) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();

    if lcsf_mode == LcsfModeEnum::Small {
        // Check if attribute has sub-attributes
        if att.has_subatt {
            // Byte 1: Attribute id + MSb at 1
            buffer.push((att_id | 0x80) as u8);
        } else {
            // Byte 1: Attribute id + MSb at 0
            buffer.push((att_id & 0x7F) as u8);
        }
        // Byte 2: Attribute data size or sub-attribute number
        buffer.push(att.payload_size as u8);
    } else {
        // Byte 1: Attribute id LSB
        buffer.push(att_id as u8);
        // Check if attribute has sub-attributes
        if att.has_subatt {
            // Byte 2: Attribute id MSB + MSb at 1
            buffer.push(((att_id >> 8) | 0x80) as u8);
        } else {
            // Byte 2: Attribute id MSB + MSb at 0
            buffer.push(((att_id >> 8) & 0x7F) as u8);
        }
        // Byte 3: Attribute data size or sub-attribute number LSB
        buffer.push(att.payload_size as u8);
        // Byte 4: Attribute data size or sub-attribute number MSB
        buffer.push((att.payload_size >> 8) as u8);
    }
    buffer
}

/// Recursively encode a LcsfRawAtt into a buffer
///
/// lcsf_mode: parsing mode to use, see [LcsfModeEnum]
///
/// att_id: attribute id value
///
/// att: attribute to encode reference
fn encode_att_rec(lcsf_mode: LcsfModeEnum, att_id: u16, att: &LcsfRawAtt) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    // Skip empty raw attributes
    if att.payload_size == 0 {
        return buffer;
    }
    // Fill attribute header
    buffer.extend(fill_att_header(lcsf_mode, att_id, att));
    // Check payload type
    match &att.payload {
        LcsfRawAttPayload::Data(data) => {
            // Recopy data
            buffer.extend(data);
        }
        LcsfRawAttPayload::SubattArr(subatt_arr) => {
            // Parse sub-attribute array
            for (sub_id, sub_att) in subatt_arr {
                // Encode sub-attribute in buffer
                buffer.extend(encode_att_rec(lcsf_mode, *sub_id, sub_att));
            }
        }
    }
    buffer
}

/// Encode a LcsfRawMsg into a buffer
///
/// lcsf_mode: parsing mode to use, see [LcsfModeEnum]
///
/// msg: message to encode reference
pub fn encode_buff(lcsf_mode: LcsfModeEnum, msg: &LcsfRawMsg) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();

    // Encode the message header
    buffer.extend(fill_msg_header(lcsf_mode, msg));
    // Encode the attribute array
    for (id, att) in &msg.att_arr {
        buffer.extend(encode_att_rec(lcsf_mode, *id, att));
    }
    buffer
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;

    #[test]
    fn test_fetch_msg_header() {
        let mut msg = (*TEST_RAW_MSG).clone();
        msg.att_arr.clear();

        // Test error
        assert_eq!(None, fetch_msg_header(LcsfModeEnum::Small, &mut [].iter()));
        // Test small
        let mut new_msg = fetch_msg_header(LcsfModeEnum::Small, &mut RX_MSG_SMALL.iter()).unwrap();
        assert_eq!(new_msg, msg);
        // Test normal
        new_msg = fetch_msg_header(LcsfModeEnum::Normal, &mut RX_MSG_NORMAL.iter()).unwrap();
        assert_eq!(new_msg, msg);
    }

    #[test]
    fn test_fetch_att_header() {
        let (att_id, mut att) = TEST_RAW_MSG.att_arr[0].clone();
        att.payload = LcsfRawAttPayload::Data(Vec::new());

        // Test error
        assert_eq!(None, fetch_att_header(LcsfModeEnum::Small, &mut [].iter()));
        // Test small
        let (mut new_id, mut new_att) =
            fetch_att_header(LcsfModeEnum::Small, &mut RX_MSG_SMALL[3..].iter()).unwrap();
        assert_eq!(new_att, att);
        assert_eq!(new_id, att_id);
        // Test normal
        (new_id, new_att) =
            fetch_att_header(LcsfModeEnum::Normal, &mut RX_MSG_NORMAL[6..].iter()).unwrap();
        assert_eq!(new_att, att);
        assert_eq!(new_id, att_id);
    }

    #[test]
    fn test_decode_att_rec() {
        let bad_att_data = [0xab, 0x12, 0x01, 0x00, 0x05, 0x01];

        // Test error
        match decode_att_rec(LcsfModeEnum::Small, &mut [].iter()) {
            Ok(_) => panic!("decode_att_rec should fail"),
            Err(err) => assert_eq!(err, LcsfDecodeErrorEnum::FormatErr),
        }
        match decode_att_rec(LcsfModeEnum::Small, &mut bad_att_data.iter()) {
            Ok(_) => panic!("decode_att_rec should fail"),
            Err(err) => assert_eq!(err, LcsfDecodeErrorEnum::FormatErr),
        }
        // Test small
        let data_iter = &mut RX_MSG_SMALL[3..].iter();
        for att_idx in 0..TEST_RAW_MSG.att_arr.len() {
            let (id, att) = &TEST_RAW_MSG.att_arr[att_idx];
            match decode_att_rec(LcsfModeEnum::Small, data_iter) {
                Ok((new_id, new_att)) => {
                    assert_eq!(new_att, *att);
                    assert_eq!(new_id, *id);
                }
                Err(err) => panic!("decode_att_rec failed with error: {err:?} but should not fail"),
            }
        }
        // Test normal
        let data_iter = &mut RX_MSG_NORMAL[6..].iter();
        for att_idx in 0..TEST_RAW_MSG.att_arr.len() {
            let (id, att) = &TEST_RAW_MSG.att_arr[att_idx];
            match decode_att_rec(LcsfModeEnum::Normal, data_iter) {
                Ok((new_id, new_att)) => {
                    assert_eq!(new_att, *att);
                    assert_eq!(new_id, *id);
                }
                Err(err) => panic!("decode_att_rec failed with error: {err:?} but should not fail"),
            }
        }
    }

    #[test]
    fn test_decode_buff() {
        let bad_fmt_msg: Vec<u8> = vec![0xab, 0x12];
        let too_long_msg: Vec<u8> = vec![0xab, 0x12, 0x01, 0x00, 0x01, 0x00, 0x55];

        // Test error
        match decode_buff(LcsfModeEnum::Small, &bad_fmt_msg) {
            Ok(_) => panic!("decode_buff should fail"),
            Err(err) => assert_eq!(err, LcsfDecodeErrorEnum::FormatErr),
        }
        match decode_buff(LcsfModeEnum::Small, &too_long_msg) {
            Ok(_) => panic!("decode_buff should fail"),
            Err(err) => assert_eq!(err, LcsfDecodeErrorEnum::FormatErr),
        }
        // Test small
        match decode_buff(LcsfModeEnum::Small, RX_MSG_SMALL) {
            Ok(new_msg) => assert_eq!(new_msg, *TEST_RAW_MSG),
            Err(err) => panic!("decode_buff failed with error: {err:?} but should not fail"),
        }
        // Test normal
        match decode_buff(LcsfModeEnum::Normal, RX_MSG_NORMAL) {
            Ok(new_msg) => assert_eq!(new_msg, *TEST_RAW_MSG),
            Err(err) => panic!("decode_buff failed with error: {err:?} but should not fail"),
        }
    }

    #[test]
    fn test_fill_msg_header() {
        // Test small
        assert_eq!(
            fill_msg_header(LcsfModeEnum::Small, &TEST_RAW_MSG),
            vec![0xab, 0x12, 0x03]
        );
        // Test normal
        assert_eq!(
            fill_msg_header(LcsfModeEnum::Normal, &TEST_RAW_MSG),
            vec![0xab, 0x00, 0x12, 0x00, 0x03, 0x00]
        );
    }

    #[test]
    fn test_fill_att_header() {
        // Test small
        assert_eq!(
            fill_att_header(
                LcsfModeEnum::Small,
                TEST_RAW_MSG.att_arr[0].0,
                &TEST_RAW_MSG.att_arr[0].1
            ),
            vec![0x55, 0x05]
        );
        assert_eq!(
            fill_att_header(
                LcsfModeEnum::Small,
                TEST_RAW_MSG.att_arr[1].0,
                &TEST_RAW_MSG.att_arr[1].1
            ),
            vec![0xff, 0x02]
        );
        // Test normal
        assert_eq!(
            fill_att_header(
                LcsfModeEnum::Normal,
                TEST_RAW_MSG.att_arr[0].0,
                &TEST_RAW_MSG.att_arr[0].1
            ),
            vec![0x55, 0x00, 0x05, 0x00]
        );
        assert_eq!(
            fill_att_header(
                LcsfModeEnum::Normal,
                TEST_RAW_MSG.att_arr[1].0,
                &TEST_RAW_MSG.att_arr[1].1
            ),
            vec![0x7f, 0x80, 0x02, 0x00]
        );
    }

    #[test]
    fn test_encode_att_rec() {
        // Test small
        assert_eq!(
            encode_att_rec(
                LcsfModeEnum::Small,
                TEST_RAW_MSG.att_arr[1].0,
                &TEST_RAW_MSG.att_arr[1].1
            ),
            RX_MSG_SMALL[10..32]
        );
        // Test normal
        assert_eq!(
            encode_att_rec(
                LcsfModeEnum::Normal,
                TEST_RAW_MSG.att_arr[1].0,
                &TEST_RAW_MSG.att_arr[1].1
            ),
            RX_MSG_NORMAL[15..45]
        );
    }

    #[test]
    fn test_encode_buff() {
        // Test small
        assert_eq!(
            encode_buff(LcsfModeEnum::Small, &TEST_RAW_MSG),
            RX_MSG_SMALL
        );
        // Test normal
        assert_eq!(
            encode_buff(LcsfModeEnum::Normal, &TEST_RAW_MSG),
            RX_MSG_NORMAL
        );
    }

    // Test data
    const RX_MSG_SMALL: &'static [u8] = &[
        0xab, 0x12, 0x03, 0x55, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0xff, 0x02, 0x30, 0x01, 0x0a,
        0xb1, 0x01, 0x32, 0x0d, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x6f, 0x6c, 0x65, 0x70, 0x74, 0x69,
        0x63, 0x00, 0x40, 0x02, 0xab, 0xcd,
    ];

    const RX_MSG_NORMAL: &'static [u8] = &[
        0xab, 0x00, 0x12, 0x00, 0x03, 0x00, 0x55, 0x00, 0x05, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x7f, 0x80, 0x02, 0x00, 0x30, 0x00, 0x01, 0x00, 0x0a, 0x31, 0x80, 0x01, 0x00, 0x32, 0x00,
        0x0d, 0x00, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x6f, 0x6c, 0x65, 0x70, 0x74, 0x69, 0x63, 0x00,
        0x40, 0x00, 0x02, 0x00, 0xab, 0xcd,
    ];

    lazy_static! {
        static ref TEST_RAW_MSG: LcsfRawMsg = LcsfRawMsg {
            prot_id: 0xab,
            cmd_id: 0x12,
            att_nb: 3,
            att_arr: vec![
                (
                    0x55,
                    LcsfRawAtt {
                        has_subatt: false,
                        payload_size: 5,
                        payload: LcsfRawAttPayload::Data(vec![0x00, 0x01, 0x02, 0x03, 0x04]),
                    }
                ),
                (
                    0x7f,
                    LcsfRawAtt {
                        has_subatt: true,
                        payload_size: 2,
                        payload: LcsfRawAttPayload::SubattArr(vec![
                            (
                                0x30,
                                LcsfRawAtt {
                                    has_subatt: false,
                                    payload_size: 1,
                                    payload: LcsfRawAttPayload::Data(vec![0xa]),
                                }
                            ),
                            (
                                0x31,
                                LcsfRawAtt {
                                    has_subatt: true,
                                    payload_size: 1,
                                    payload: LcsfRawAttPayload::SubattArr(vec![(
                                        0x32,
                                        LcsfRawAtt {
                                            has_subatt: false,
                                            payload_size: 13,
                                            payload: LcsfRawAttPayload::Data(vec![
                                                0x4f, 0x72, 0x67, 0x61, 0x6e, 0x6f, 0x6c, 0x65,
                                                0x70, 0x74, 0x69, 0x63, 0x00,
                                            ]),
                                        }
                                    ),])
                                }
                            ),
                        ])
                    }
                ),
                (
                    0x40,
                    LcsfRawAtt {
                        has_subatt: false,
                        payload_size: 2,
                        payload: LcsfRawAttPayload::Data(vec![0xab, 0xcd]),
                    }
                ),
            ],
        };
    }
}
