/// author: Jean-Roland Gosse
/// desc: Light Command Set Format core module
///
/// This file is part of LCSF Stack Rust.
/// Spec details at https://jean-roland.github.io/LCSF_Doc/
/// You should have received a copy of the GNU Lesser General Public License
/// along with this program. If not, see <https://www.gnu.org/licenses/>
use std::collections::HashMap;

use crate::lcsf_error;
use crate::lcsf_transcoder;
use crate::lcsf_validator;
use lcsf_error::LcsfEpLocEnum;
use lcsf_error::LCSF_EP_PROT_DESC;
use lcsf_transcoder::LcsfModeEnum;
use lcsf_validator::LcsfCmdDesc;
use lcsf_validator::LcsfProtDesc;
use lcsf_validator::LcsfValidCmd;

// Callback prototype
pub type ProtCallback = fn(LcsfValidCmd); // Called to process a valid command
pub type SendCallback = fn(Vec<u8>); // Called to send a byte array message

pub struct LcsfCore {
    do_gen_err: bool, // Activate lcsf error packet generation if message decoding fails
    lcsf_mode: LcsfModeEnum, // Lcsf representation mode to use
    fn_send: SendCallback, // Send byte array callback
    prot_desc_map: HashMap<u16, &'static LcsfProtDesc>, // Protocol descriptions hash map
    prot_cb_map: HashMap<u16, ProtCallback>, // Protocol callbacks hash map
}

/// Default function to process received errors, replace as needed through update_err_cb()
/// \param valid_cmd validated error command
fn def_process_error(valid_cmd: LcsfValidCmd) {
    let (loc_str, type_str) = lcsf_error::process_error(&valid_cmd);
    println!(
        "[{}:{}]: Received error, location: {loc_str}, type: {type_str}",
        module_path!(),
        line!()
    );
}

impl LcsfCore {
    /// Create an instance of a LcsfCore
    /// \param mode lcsf representation mode to use
    /// \param send_cb callback to send byte array
    /// \param do_gen_err control lcsf error packet generation
    pub fn new(mode: LcsfModeEnum, send_cb: SendCallback, do_gen_err: bool) -> Self {
        let err_prot_id = match mode {
            LcsfModeEnum::Small => lcsf_error::LCSF_EP_PROT_ID_SMALL,
            _ => lcsf_error::LCSF_EP_PROT_ID_NORMAL,
        };
        LcsfCore {
            do_gen_err: do_gen_err,
            lcsf_mode: mode,
            fn_send: send_cb,
            prot_desc_map: HashMap::from([(err_prot_id, &LCSF_EP_PROT_DESC as &LcsfProtDesc)]),
            prot_cb_map: HashMap::from([(err_prot_id, def_process_error as ProtCallback)]),
        }
    }

    /// Change the error processing callback
    /// \param new_err_cb new error callback
    #[allow(dead_code)]
    pub fn update_err_cb(&mut self, new_err_cb: ProtCallback) {
        let err_prot_id = match self.lcsf_mode {
            LcsfModeEnum::Small => lcsf_error::LCSF_EP_PROT_ID_SMALL,
            _ => lcsf_error::LCSF_EP_PROT_ID_NORMAL,
        };
        self.prot_cb_map.insert(err_prot_id, new_err_cb);
    }

    /// Add a protocol
    /// \param prot_id protocol id
    /// \param prot_desc protocol descriptor reference
    /// \param prot_cb protocol callback
    pub fn add_protocol(
        &mut self,
        prot_id: u16,
        prot_desc: &'static LcsfProtDesc,
        prot_cb: ProtCallback,
    ) {
        self.prot_desc_map.insert(prot_id, prot_desc);
        self.prot_cb_map.insert(prot_id, prot_cb);
    }

    /// Process an incoming lcsf message
    /// \param buff buffer reference
    pub fn receive_buff(&self, buff: &[u8]) -> bool {
        // Send to transcoder
        let raw_msg = match lcsf_transcoder::decode_buff(self.lcsf_mode, buff) {
            Err(err) => {
                println!("decode_buff failed with err {err:?}");
                if self.do_gen_err {
                    // Generate and send error
                    let buff = lcsf_error::encode_error(
                        self.lcsf_mode,
                        LcsfEpLocEnum::DecodeError,
                        err as u8,
                    );
                    (self.fn_send)(buff);
                }
                return false;
            }
            Ok(msg) => msg,
        };
        // Send to validator
        let (valid_msg, prot_id) = match lcsf_validator::validate_msg(&self.prot_desc_map, &raw_msg)
        {
            Err(err) => {
                println!("validate_msg failed with err {err:?}");
                if self.do_gen_err {
                    // Generate and send error
                    let buff = lcsf_error::encode_error(
                        self.lcsf_mode,
                        LcsfEpLocEnum::ValidationError,
                        err as u8,
                    );
                    (self.fn_send)(buff);
                }
                return false;
            }
            Ok((msg, id)) => (msg, id),
        };
        // Dispatch command
        let prot_cb = self.prot_cb_map.get(&prot_id).unwrap();
        prot_cb(valid_msg);
        return true;
    }

    /// Send an outgoing valid command
    /// \param prot_id protocol id
    /// \param valid_cmd valid command reference
    pub fn send_cmd(&self, prot_id: u16, valid_cmd: &LcsfValidCmd) {
        // Retrieve cmd desc
        let prot_desc = self.prot_desc_map.get(&prot_id).unwrap();
        let cmd_desc_map: HashMap<u16, LcsfCmdDesc> =
            prot_desc.cmd_desc_arr.iter().cloned().collect();
        let cmd_desc = cmd_desc_map.get(&valid_cmd.cmd_id).unwrap();

        let raw_msg = lcsf_validator::encode_valid(prot_id, &cmd_desc, &valid_cmd).unwrap();
        let buff = lcsf_transcoder::encode_buff(self.lcsf_mode, &raw_msg);
        // Send buffer
        (self.fn_send)(buff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;

    // Mock for SendCallback
    fn dummy_send_callback(_: Vec<u8>) {
        // Mock implementation
    }

    // Mock for ProtCallback
    fn dummy_prot_callback(_: LcsfValidCmd) {}

    lazy_static! {
        static ref TEST_PROT_DESC: LcsfProtDesc = LcsfProtDesc {
            cmd_desc_arr: vec![(
                0x12,
                LcsfCmdDesc {
                    att_desc_arr: Vec::new(),
                }
            ),]
        };
        static ref TEST_VALID_CMD: LcsfValidCmd = LcsfValidCmd {
            cmd_id: 0x12,
            att_arr: Vec::new(),
        };
        static ref TEST_BUFF: Vec<u8> = vec![0xab, 0x12, 0x00];
    }

    #[test]
    fn test_new_lcsf_core() {
        let lcsf_core = LcsfCore::new(LcsfModeEnum::Normal, dummy_send_callback, false);
        // Assert that the instance is created correctly
        assert_eq!(lcsf_core.lcsf_mode, LcsfModeEnum::Normal);
        if lcsf_core.fn_send != dummy_send_callback {
            panic!("Invalid callback pointer");
        }
    }

    #[test]
    fn test_update_err_cb() {
        let mut lcsf_core = LcsfCore::new(LcsfModeEnum::Normal, dummy_send_callback, false);
        // Check current callback
        let err_prot_id = lcsf_error::LCSF_EP_PROT_ID_NORMAL;
        let mut error_callback = lcsf_core.prot_cb_map.get(&err_prot_id).unwrap();
        if *error_callback != def_process_error as fn(LcsfValidCmd) {
            panic!("Invalid callback pointer");
        }
        // Update the error callback
        lcsf_core.update_err_cb(dummy_prot_callback);
        // Assert that the error callback is updated correctly
        error_callback = lcsf_core.prot_cb_map.get(&err_prot_id).unwrap();
        if *error_callback != dummy_prot_callback as fn(LcsfValidCmd) {
            panic!("Invalid callback pointer");
        }
    }

    #[test]
    fn test_add_protocol() {
        let mut lcsf_core = LcsfCore::new(LcsfModeEnum::Normal, dummy_send_callback, false);
        // Add protocol
        lcsf_core.add_protocol(0xab, &TEST_PROT_DESC, dummy_prot_callback);
        // Check values
        let prot_desc = lcsf_core.prot_desc_map.get(&0xab).unwrap();
        let callback = lcsf_core.prot_cb_map.get(&0xab).unwrap();
        assert_eq!(**prot_desc, *TEST_PROT_DESC);
        if *callback != dummy_prot_callback as fn(LcsfValidCmd) {
            panic!("Invalid callback pointer");
        }
    }

    use std::sync::atomic::{AtomicBool, Ordering};

    static CMD_IS_VALID: AtomicBool = AtomicBool::new(false);

    fn test_prot_callback(valid_cmd: LcsfValidCmd) {
        if valid_cmd == *TEST_VALID_CMD {
            CMD_IS_VALID.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_receive_buff() {
        let mut lcsf_core = LcsfCore::new(LcsfModeEnum::Small, dummy_send_callback, false);
        // Add protocol
        lcsf_core.add_protocol(0xab, &TEST_PROT_DESC, test_prot_callback);
        // Test function
        assert!(lcsf_core.receive_buff(&TEST_BUFF));
        // Check value
        let is_valid: bool = CMD_IS_VALID.load(Ordering::SeqCst);
        assert!(is_valid);
    }

    static BUFF_IS_VALID: AtomicBool = AtomicBool::new(false);

    fn test_send_callback(buff: Vec<u8>) {
        if buff == *TEST_BUFF {
            BUFF_IS_VALID.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_send_cmd() {
        let mut lcsf_core = LcsfCore::new(LcsfModeEnum::Small, test_send_callback, false);
        // Add protocol
        lcsf_core.add_protocol(0xab, &TEST_PROT_DESC, dummy_prot_callback);
        // Test function
        lcsf_core.send_cmd(0xab, &TEST_VALID_CMD);
        let is_valid: bool = BUFF_IS_VALID.load(Ordering::SeqCst);
        assert!(is_valid);
    }

    static ERR_IS_VALID: AtomicBool = AtomicBool::new(false);

    fn test_err_callback(valid_cmd: LcsfValidCmd) {
        let (loc_str, type_str) = lcsf_error::process_error(&valid_cmd);
        if loc_str == "Validator" && type_str == "Unknown attribute id" {
            ERR_IS_VALID.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_error_processing() {
        // Test data
        let err_buff: Vec<u8> = vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02];

        let mut lcsf_core = LcsfCore::new(LcsfModeEnum::Small, dummy_send_callback, false);
        // Update the error callback
        lcsf_core.update_err_cb(test_err_callback);
        // Send buffer
        assert!(lcsf_core.receive_buff(&err_buff));
        // Check value
        let is_valid: bool = ERR_IS_VALID.load(Ordering::SeqCst);
        assert!(is_valid);
    }

    static BAD_DATA_IS_VALID: AtomicBool = AtomicBool::new(false);

    fn test_bad_data_callback(buff: Vec<u8>) {
        let bad_data: Vec<u8> = vec![0xff, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00];

        if buff == bad_data {
            BAD_DATA_IS_VALID.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_error_encoding() {
        // Test data
        let bad_buff: Vec<u8> = vec![0xab, 0x12, 0x05]; // Bad format error

        let lcsf_core = LcsfCore::new(LcsfModeEnum::Small, test_bad_data_callback, true);
        // Send buffer
        assert!(!lcsf_core.receive_buff(&bad_buff));
        // Check value
        let is_valid: bool = BAD_DATA_IS_VALID.load(Ordering::SeqCst);
        assert!(is_valid);
    }
}
