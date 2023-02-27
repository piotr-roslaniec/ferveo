#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]

use ark_ec::pairing::Pairing;
use serde::{Deserialize, Serialize};

pub mod common;
pub mod pv;

pub use common::*;
pub use pv::*;

// DKG parameters
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    pub tau: u64,
    pub security_threshold: u32,
    pub shares_num: u32,
}

#[derive(Debug, Clone)]
pub enum DkgState<E: Pairing> {
    Sharing { accumulated_shares: u32, block: u32 },
    Dealt,
    Success { final_key: E::G1Affine },
    Invalid,
}
