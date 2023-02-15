#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use anyhow::anyhow;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_ff::{Field, One};
use ark_poly::{
    polynomial::univariate::DensePolynomial, EvaluationDomain, Polynomial,
};
use ark_serialize::*;
use bincode::Options;
use ed25519_dalek as ed25519;
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
