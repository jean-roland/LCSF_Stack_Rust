//! Main file (A) for protocol: Test
//!
//! This file has been auto-generated by LCSF Generator v1.3
//! Feel free to customize as needed
//!
//! edited by: Jean-Roland Gosse

use crate::lcsf_lib::lcsf_core;
use crate::lcsf_lib::lcsf_validator;
use crate::lcsf_prot::lcsf_protocol_test;
use lcsf_core::LcsfCore;
use lcsf_validator::LcsfValidCmd;
use std::ffi::CString;

/// Command enum
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CmdEnum {
    Sc1,
    Sc2,
    Sc3,
    Cc1,
    Cc2,
    Cc3,
    Cc4,
    Cc5,
    Cc6,
}

/// Command payload union
#[derive(Debug, PartialEq)]
pub enum CmdPayload {
    Empty,
    Cc1Payload(Cc1AttPayload),
    Cc2Payload(Cc2AttPayload),
    Cc3Payload(Cc3AttPayload),
    Cc4Payload(Cc4AttPayload),
    Cc5Payload(Cc5AttPayload),
    Cc6Payload(Cc6AttPayload),
}

// Command data structures
#[derive(Debug, PartialEq)]
pub struct Cc1AttPayload {
    pub sa1: u8,
    pub sa2: u16,
    pub sa3: u32,
    pub sa4: Vec<u8>,
    pub sa5: CString,
    pub is_sa6_here: bool,
    pub sa6: u8,
    pub is_sa7_here: bool,
    pub sa7: u16,
    pub is_sa8_here: bool,
    pub sa8: u32,
    pub is_sa9_here: bool,
    pub sa9: Vec<u8>,
    pub is_sa10_here: bool,
    pub sa10: CString,
    pub sa11: u64,
    pub sa12: f32,
    pub sa13: f64,
}

#[derive(Debug, PartialEq)]
pub struct Cc2AttPayload {
    pub sa1: u8,
    pub sa2: u16,
    pub sa3: u32,
    pub sa4: Vec<u8>,
    pub sa5: CString,
    pub is_sa6_here: bool,
    pub sa6: u8,
    pub is_sa7_here: bool,
    pub sa7: u16,
    pub is_sa8_here: bool,
    pub sa8: u32,
    pub is_sa9_here: bool,
    pub sa9: Vec<u8>,
    pub is_sa10_here: bool,
    pub sa10: CString,
    pub sa11: u64,
    pub sa12: f32,
    pub sa13: f64,
}

#[derive(Debug, PartialEq)]
pub struct Cc3AttPayload {
    pub sa1: u8,
    pub sa2: u16,
    pub sa3: u32,
    pub sa4: Vec<u8>,
    pub sa5: CString,
    pub is_sa6_here: bool,
    pub sa6: u8,
    pub is_sa7_here: bool,
    pub sa7: u16,
    pub is_sa8_here: bool,
    pub sa8: u32,
    pub is_sa9_here: bool,
    pub sa9: Vec<u8>,
    pub is_sa10_here: bool,
    pub sa10: CString,
    pub sa11: u64,
    pub sa12: f32,
    pub sa13: f64,
}

#[derive(Debug, PartialEq)]
pub struct Cc4AttPayload {
    pub sa1: u8,
    pub ca1_payload: Cc4AttCa1Payload,
    pub is_ca2_here: bool,
    pub ca2_payload: Cc4AttCa2Payload,
}

#[derive(Debug, PartialEq)]
pub struct Cc5AttPayload {
    pub sa2: u16,
    pub ca5_payload: Cc5AttCa5Payload,
    pub is_ca6_here: bool,
    pub ca6_payload: Cc5AttCa6Payload,
}

#[derive(Debug, PartialEq)]
pub struct Cc6AttPayload {
    pub sa4: Vec<u8>,
    pub ca9_payload: Cc6AttCa9Payload,
    pub is_ca10_here: bool,
    pub ca10_payload: Cc6AttCa10Payload,
}

// Attribute with sub-attributes structures
#[derive(Debug, PartialEq)]
pub struct Cc4AttCa1Payload {
    pub sa1: u8,
    pub sa2: u16,
    pub is_sa3_here: bool,
    pub sa3: u32,
}

#[derive(Debug, PartialEq)]
pub struct Cc4AttCa2Payload {
    pub is_sa1_here: bool,
    pub sa1: u8,
    pub ca3_payload: Ca2AttCa3Payload,
}

#[derive(Debug, PartialEq)]
pub struct Ca2AttCa3Payload {
    pub is_sa1_here: bool,
    pub sa1: u8,
    pub ca4_payload: Ca3AttCa4Payload,
}

#[derive(Debug, PartialEq)]
pub struct Ca3AttCa4Payload {
    pub sa4: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Cc5AttCa5Payload {
    pub sa1: u8,
    pub sa2: u16,
    pub is_sa3_here: bool,
    pub sa3: u32,
}

#[derive(Debug, PartialEq)]
pub struct Cc5AttCa6Payload {
    pub is_sa1_here: bool,
    pub sa1: u8,
    pub ca7_payload: Ca6AttCa7Payload,
}

#[derive(Debug, PartialEq)]
pub struct Ca6AttCa7Payload {
    pub is_sa1_here: bool,
    pub sa1: u8,
    pub ca8_payload: Ca7AttCa8Payload,
}

#[derive(Debug, PartialEq)]
pub struct Ca7AttCa8Payload {
    pub sa4: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Cc6AttCa9Payload {
    pub sa1: u8,
    pub sa2: u16,
    pub is_sa3_here: bool,
    pub sa3: u32,
}

#[derive(Debug, PartialEq)]
pub struct Cc6AttCa10Payload {
    pub is_sa1_here: bool,
    pub sa1: u8,
    pub ca11_payload: Ca10AttCa11Payload,
}

#[derive(Debug, PartialEq)]
pub struct Ca10AttCa11Payload {
    pub is_sa1_here: bool,
    pub sa1: u8,
    pub ca12_payload: Ca11AttCa12Payload,
}

#[derive(Debug, PartialEq)]
pub struct Ca11AttCa12Payload {
    pub sa4: Vec<u8>,
}

// Command execution functions, customize as you need
fn execute_sc2() -> (CmdEnum, CmdPayload) {
    // Send sc1
    (CmdEnum::Sc1, CmdPayload::Empty)
}

fn execute_sc3() -> (CmdEnum, CmdPayload) {
    // Send sc3
    (CmdEnum::Sc3, CmdPayload::Empty)
}

fn execute_cc2(payload: &Cc2AttPayload) -> (CmdEnum, CmdPayload) {
    // Retrieve attributes
    let sa1 = payload.sa1;
    let sa2 = payload.sa2;
    let sa3 = payload.sa3;
    let sa4 = &payload.sa4;
    let sa5 = &payload.sa5;
    let mut sa6 = 0;
    let mut sa7 = 0;
    let mut sa8 = 0;
    let mut sa9 = &Vec::new();
    let mut sa10 = &CString::new("").unwrap();
    let sa11 = payload.sa11;
    let sa12 = payload.sa12;
    let sa13 = payload.sa13;
    if payload.is_sa6_here {
        sa6 = payload.sa6;
    }
    if payload.is_sa7_here {
        sa7 = payload.sa7;
    }
    if payload.is_sa8_here {
        sa8 = payload.sa8;
    }
    if payload.is_sa9_here {
        sa9 = &payload.sa9;
    }
    if payload.is_sa10_here {
        sa10 = &payload.sa10;
    }
    // Process data
    let mut send_payload = Cc1AttPayload {
        sa1: sa1 + 1,
        sa2: sa2 + 1,
        sa3: sa3 + 1,
        sa4: Vec::new(),
        sa5: CString::new("").unwrap(),
        is_sa6_here: payload.is_sa6_here,
        is_sa7_here: payload.is_sa7_here,
        is_sa8_here: payload.is_sa8_here,
        is_sa9_here: payload.is_sa9_here,
        is_sa10_here: payload.is_sa10_here,
        sa6: sa6 + 1,
        sa7: sa7 + 1,
        sa8: sa8 + 1,
        sa9: Vec::new(),
        sa10: CString::new("").unwrap(),
        sa11: sa11 + 1,
        sa12: sa12 + 1.0,
        sa13: sa13 + 1.0,
    };
    for byte in sa4 {
        send_payload.sa4.push(*byte + 1);
    }
    let mut tmp_str = sa5.to_string_lossy().to_string();
    tmp_str = tmp_str.chars().rev().collect();
    send_payload.sa5 = CString::new(tmp_str).unwrap();

    if payload.is_sa9_here {
        for byte in sa9 {
            send_payload.sa9.push(*byte + 1);
        }
    }
    if payload.is_sa10_here {
        let mut tmp_str = sa10.to_string_lossy().to_string();
        tmp_str = tmp_str.chars().rev().collect();
        send_payload.sa10 = CString::new(tmp_str).unwrap();
    }
    // Send cc1
    (CmdEnum::Cc1, CmdPayload::Cc1Payload(send_payload))
}

fn execute_cc3(payload: &Cc3AttPayload) -> (CmdEnum, CmdPayload) {
    // Retrieve attributes
    let sa1 = payload.sa1;
    let sa2 = payload.sa2;
    let sa3 = payload.sa3;
    let sa4 = &payload.sa4;
    let sa5 = &payload.sa5;
    let mut sa6 = 0;
    let mut sa7 = 0;
    let mut sa8 = 0;
    let mut sa9 = &Vec::new();
    let mut sa10 = &CString::new("").unwrap();
    let sa11 = payload.sa11;
    let sa12 = payload.sa12;
    let sa13 = payload.sa13;
    if payload.is_sa6_here {
        sa6 = payload.sa6;
    }
    if payload.is_sa7_here {
        sa7 = payload.sa7;
    }
    if payload.is_sa8_here {
        sa8 = payload.sa8;
    }
    if payload.is_sa9_here {
        sa9 = &payload.sa9;
    }
    if payload.is_sa10_here {
        sa10 = &payload.sa10;
    }
    // // Process data
    let mut send_payload = Cc3AttPayload {
        sa1: (sa1 as u16 + 1) as u8,
        sa2: (sa2 as u32 + 1) as u16,
        sa3: sa3 + 1,
        sa4: Vec::new(),
        sa5: CString::new("").unwrap(),
        is_sa6_here: payload.is_sa6_here,
        is_sa7_here: payload.is_sa7_here,
        is_sa8_here: payload.is_sa8_here,
        is_sa9_here: payload.is_sa9_here,
        is_sa10_here: payload.is_sa10_here,
        sa6: sa6 + 1,
        sa7: (sa7 as u32 + 1) as u16,
        sa8: sa8 + 1,
        sa9: Vec::new(),
        sa10: CString::new("").unwrap(),
        sa11: sa11 + 1,
        sa12: sa12 + 1.0,
        sa13: sa13 + 1.0,
    };
    for byte in sa4 {
        send_payload.sa4.push(*byte + 1);
    }
    let mut tmp_str = sa5.to_string_lossy().to_string();
    tmp_str = tmp_str.chars().rev().collect();
    send_payload.sa5 = CString::new(tmp_str).unwrap();

    if payload.is_sa9_here {
        for byte in sa9 {
            send_payload.sa9.push((*byte as u16 + 1) as u8);
        }
    }
    if payload.is_sa10_here {
        let mut tmp_str = sa10.to_string_lossy().to_string();
        tmp_str = tmp_str.chars().rev().collect();
        send_payload.sa10 = CString::new(tmp_str).unwrap();
    }
    // Send CC3
    (CmdEnum::Cc3, CmdPayload::Cc3Payload(send_payload))
}

fn execute_cc5(payload: &Cc5AttPayload) -> (CmdEnum, CmdPayload) {
    // Retrieve attributes data
    let sa2 = payload.sa2;
    let ca5_sa1 = payload.ca5_payload.sa1;
    let ca5_sa2 = payload.ca5_payload.sa2;
    let mut ca5_sa3 = 0;
    let mut ca6_sa1 = 0;
    let mut ca7_sa1 = 0;
    let mut ca8_sa4 = &Vec::new();
    if payload.ca5_payload.is_sa3_here {
        ca5_sa3 = payload.ca5_payload.sa3;
    }
    if payload.is_ca6_here {
        if payload.ca6_payload.is_sa1_here {
            ca6_sa1 = payload.ca6_payload.sa1;
        }
        if payload.ca6_payload.ca7_payload.is_sa1_here {
            ca7_sa1 = payload.ca6_payload.ca7_payload.sa1;
        }
        ca8_sa4 = &payload.ca6_payload.ca7_payload.ca8_payload.sa4;
    }
    // Process data
    let mut send_payload = Cc4AttPayload {
        is_ca2_here: payload.is_ca6_here,
        sa1: (sa2 + 1) as u8,
        ca1_payload: Cc4AttCa1Payload {
            is_sa3_here: payload.ca5_payload.is_sa3_here,
            sa1: ca5_sa1 + 1,
            sa2: ca5_sa2 + 1,
            sa3: ca5_sa3 + 1,
        },
        ca2_payload: Cc4AttCa2Payload {
            is_sa1_here: payload.ca6_payload.is_sa1_here,
            sa1: ca6_sa1 + 1,
            ca3_payload: Ca2AttCa3Payload {
                is_sa1_here: payload.ca6_payload.ca7_payload.is_sa1_here,
                sa1: ca7_sa1 + 1,
                ca4_payload: Ca3AttCa4Payload { sa4: Vec::new() },
            },
        },
    };
    if payload.is_ca6_here {
        for byte in ca8_sa4 {
            send_payload
                .ca2_payload
                .ca3_payload
                .ca4_payload
                .sa4
                .push(*byte + 1);
        }
    }
    // Send CC4
    (CmdEnum::Cc4, CmdPayload::Cc4Payload(send_payload))
}

fn execute_cc6(payload: &Cc6AttPayload) -> (CmdEnum, CmdPayload) {
    // Retrieve attributes
    let sa4 = &payload.sa4;
    let ca9_sa1 = payload.ca9_payload.sa1;
    let ca9_sa2 = payload.ca9_payload.sa2;
    let mut ca9_sa3 = 0;
    let mut ca10_sa1 = 0;
    let mut ca11_sa1 = 0;
    let mut ca12_sa4 = &Vec::new();
    if payload.ca9_payload.is_sa3_here {
        ca9_sa3 = payload.ca9_payload.sa3;
    }
    if payload.is_ca10_here {
        if payload.ca10_payload.is_sa1_here {
            ca10_sa1 = payload.ca10_payload.sa1;
        }
        if payload.ca10_payload.ca11_payload.is_sa1_here {
            ca11_sa1 = payload.ca10_payload.ca11_payload.sa1;
        }
        ca12_sa4 = &payload.ca10_payload.ca11_payload.ca12_payload.sa4;
    }
    // Process data
    let mut send_payload = Cc6AttPayload {
        is_ca10_here: payload.is_ca10_here,
        sa4: Vec::new(),
        ca9_payload: Cc6AttCa9Payload {
            is_sa3_here: payload.ca9_payload.is_sa3_here,
            sa1: ca9_sa1 + 1,
            sa2: ca9_sa2 + 1,
            sa3: ca9_sa3 + 1,
        },
        ca10_payload: Cc6AttCa10Payload {
            is_sa1_here: payload.ca10_payload.is_sa1_here,
            sa1: ca10_sa1 + 1,
            ca11_payload: Ca10AttCa11Payload {
                is_sa1_here: payload.ca10_payload.ca11_payload.is_sa1_here,
                sa1: ca11_sa1 + 1,
                ca12_payload: Ca11AttCa12Payload { sa4: Vec::new() },
            },
        },
    };
    for byte in sa4 {
        send_payload.sa4.push(*byte + 1);
    }
    if payload.is_ca10_here {
        for byte in ca12_sa4 {
            send_payload
                .ca10_payload
                .ca11_payload
                .ca12_payload
                .sa4
                .push(*byte + 1);
        }
    }
    // Send CC6
    (CmdEnum::Cc6, CmdPayload::Cc6Payload(send_payload))
}

/// Execute a command, customize as needed
///
/// cmd_name: name of the command
///
/// cmd_payload: pointer to command payload
fn execute_cmd(cmd_name: CmdEnum, cmd_payload: &CmdPayload) -> (CmdEnum, CmdPayload) {
    match cmd_name {
        CmdEnum::Sc2 => return execute_sc2(),
        CmdEnum::Sc3 => return execute_sc3(),
        CmdEnum::Cc2 => {
            if let CmdPayload::Cc2Payload(payload) = cmd_payload {
                return execute_cc2(payload);
            }
        }
        CmdEnum::Cc3 => {
            if let CmdPayload::Cc3Payload(payload) = cmd_payload {
                return execute_cc3(payload);
            }
        }
        CmdEnum::Cc5 => {
            if let CmdPayload::Cc5Payload(payload) = cmd_payload {
                return execute_cc5(payload);
            }
        }
        CmdEnum::Cc6 => {
            if let CmdPayload::Cc6Payload(payload) = cmd_payload {
                return execute_cc6(payload);
            }
        }
        _ => {}
    }
    (CmdEnum::Sc1, CmdPayload::Empty)
}

/// Init a LcsfCore with the protocol
///
/// core: LcsfCore reference
pub fn init_core(core: &mut LcsfCore) {
    // Add protocol to LcsfCore
    core.add_protocol(
        lcsf_protocol_test::PROT_ID,
        &lcsf_protocol_test::PROT_DESC,
        process_cmd,
    );
}

/// Process command callback, customize as you need
///
/// valid_cmd: received valid command
fn process_cmd(core: &LcsfCore, valid_cmd: &LcsfValidCmd) {
    // Process received command
    let (mut cmd_name, mut cmd_payload) = lcsf_protocol_test::receive_cmd(valid_cmd);
    (cmd_name, cmd_payload) = execute_cmd(cmd_name, &cmd_payload);
    // Send instant reply from execute functions
    // Customize as needed
    let valid_cmd = lcsf_protocol_test::send_cmd(cmd_name, &cmd_payload);
    core.send_cmd(lcsf_protocol_test::PROT_ID, &valid_cmd);
}

// Note: Unit tests will not be generated by Lcsf_Generator
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_cmd() {
        // Test data
        let cc2_payload = Cc2AttPayload {
            is_sa6_here: true,
            is_sa7_here: false,
            is_sa8_here: true,
            is_sa9_here: true,
            is_sa10_here: true,
            sa1: 0,
            sa2: 2000,
            sa3: 100000,
            sa4: vec![5, 4, 3, 2, 1],
            sa5: CString::new("Bob").unwrap(),
            sa6: 3,
            sa7: 12,
            sa8: 149999,
            sa9: vec![1, 2, 3, 4, 5],
            sa10: CString::new("Paul").unwrap(),
            sa11: 5000000000,
            sa12: 1.61803398875,
            sa13: 3.14159265359,
        };
        let cc1_payload = Cc1AttPayload {
            is_sa6_here: true,
            is_sa7_here: false,
            is_sa8_here: true,
            is_sa9_here: true,
            is_sa10_here: true,
            sa1: 1,
            sa2: 2001,
            sa3: 100001,
            sa4: vec![6, 5, 4, 3, 2],
            sa5: CString::new("boB").unwrap(),
            sa6: 4,
            sa7: 1,
            sa8: 150000,
            sa9: vec![2, 3, 4, 5, 6],
            sa10: CString::new("luaP").unwrap(),
            sa11: 5000000001,
            sa12: 2.61803398875,
            sa13: 4.14159265359,
        };
        let cc3_payload = Cc3AttPayload {
            is_sa6_here: true,
            is_sa7_here: true,
            is_sa8_here: true,
            is_sa9_here: false,
            is_sa10_here: true,
            sa1: 0,
            sa2: 2000,
            sa3: 100000,
            sa4: vec![5, 4, 3, 2, 1],
            sa5: CString::new("Teeth").unwrap(),
            sa6: 3,
            sa7: 4000,
            sa8: 149999,
            sa9: Vec::new(),
            sa10: CString::new("Nostril").unwrap(),
            sa11: 5000000000,
            sa12: 1.61803398875,
            sa13: 3.14159265359,
        };
        let cc3u_payload = Cc3AttPayload {
            is_sa6_here: true,
            is_sa7_here: true,
            is_sa8_here: true,
            is_sa9_here: false,
            is_sa10_here: true,
            sa1: 1,
            sa2: 2001,
            sa3: 100001,
            sa4: vec![6, 5, 4, 3, 2],
            sa5: CString::new("hteeT").unwrap(),
            sa6: 4,
            sa7: 4001,
            sa8: 150000,
            sa9: Vec::new(),
            sa10: CString::new("lirtsoN").unwrap(),
            sa11: 5000000001,
            sa12: 2.61803398875,
            sa13: 4.14159265359,
        };
        let cc5_payload = Cc5AttPayload {
            is_ca6_here: true,
            sa2: 255,
            ca5_payload: Cc5AttCa5Payload {
                is_sa3_here: false,
                sa1: 1,
                sa2: 2000,
                sa3: 40,
            },
            ca6_payload: Cc5AttCa6Payload {
                is_sa1_here: false,
                sa1: 9,
                ca7_payload: Ca6AttCa7Payload {
                    is_sa1_here: true,
                    sa1: 3,
                    ca8_payload: Ca7AttCa8Payload {
                        sa4: vec![10, 20, 30, 40, 50],
                    },
                },
            },
        };
        let cc4_payload = Cc4AttPayload {
            is_ca2_here: true,
            sa1: 0,
            ca1_payload: Cc4AttCa1Payload {
                is_sa3_here: false,
                sa1: 2,
                sa2: 2001,
                sa3: 1,
            },
            ca2_payload: Cc4AttCa2Payload {
                is_sa1_here: false,
                sa1: 1,
                ca3_payload: Ca2AttCa3Payload {
                    is_sa1_here: true,
                    sa1: 4,
                    ca4_payload: Ca3AttCa4Payload {
                        sa4: vec![11, 21, 31, 41, 51],
                    },
                },
            },
        };
        let cc6_payload = Cc6AttPayload {
            is_ca10_here: true,
            sa4: vec![0xde, 0xad],
            ca9_payload: Cc6AttCa9Payload {
                is_sa3_here: false,
                sa1: 1,
                sa2: 2000,
                sa3: 0,
            },
            ca10_payload: Cc6AttCa10Payload {
                is_sa1_here: false,
                sa1: 0,
                ca11_payload: Ca10AttCa11Payload {
                    is_sa1_here: true,
                    sa1: 3,
                    ca12_payload: Ca11AttCa12Payload {
                        sa4: vec![5, 5, 5, 5, 5],
                    },
                },
            },
        };
        let cc6u_payload = Cc6AttPayload {
            is_ca10_here: true,
            sa4: vec![0xdf, 0xae],
            ca9_payload: Cc6AttCa9Payload {
                is_sa3_here: false,
                sa1: 2,
                sa2: 2001,
                sa3: 1,
            },
            ca10_payload: Cc6AttCa10Payload {
                is_sa1_here: false,
                sa1: 1,
                ca11_payload: Ca10AttCa11Payload {
                    is_sa1_here: true,
                    sa1: 4,
                    ca12_payload: Ca11AttCa12Payload {
                        sa4: vec![6, 6, 6, 6, 6],
                    },
                },
            },
        };
        // Tests
        let (mut cmd_name, mut cmd_payload) = execute_cmd(CmdEnum::Sc2, &CmdPayload::Empty);
        assert_eq!(cmd_name, CmdEnum::Sc1);
        assert_eq!(cmd_payload, CmdPayload::Empty);

        (cmd_name, cmd_payload) = execute_cmd(CmdEnum::Sc3, &CmdPayload::Empty);
        assert_eq!(cmd_name, CmdEnum::Sc3);
        assert_eq!(cmd_payload, CmdPayload::Empty);

        (cmd_name, cmd_payload) = execute_cmd(CmdEnum::Cc2, &CmdPayload::Cc2Payload(cc2_payload));
        assert_eq!(cmd_name, CmdEnum::Cc1);
        assert_eq!(cmd_payload, CmdPayload::Cc1Payload(cc1_payload));

        (cmd_name, cmd_payload) = execute_cmd(CmdEnum::Cc3, &CmdPayload::Cc3Payload(cc3_payload));
        assert_eq!(cmd_name, CmdEnum::Cc3);
        assert_eq!(cmd_payload, CmdPayload::Cc3Payload(cc3u_payload));

        (cmd_name, cmd_payload) = execute_cmd(CmdEnum::Cc5, &CmdPayload::Cc5Payload(cc5_payload));
        assert_eq!(cmd_name, CmdEnum::Cc4);
        assert_eq!(cmd_payload, CmdPayload::Cc4Payload(cc4_payload));

        (cmd_name, cmd_payload) = execute_cmd(CmdEnum::Cc6, &CmdPayload::Cc6Payload(cc6_payload));
        assert_eq!(cmd_name, CmdEnum::Cc6);
        assert_eq!(cmd_payload, CmdPayload::Cc6Payload(cc6u_payload));
    }
}
