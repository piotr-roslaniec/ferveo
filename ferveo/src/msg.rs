use std::collections::HashMap;

use anyhow::{anyhow, Result};
use ark_ec::{msm::FixedBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain,
};
use ark_std::{end_timer, start_timer};
use ed25519_dalek as ed25519;
use ed25519_dalek::Signer;
use ferveo_common::Rng;
use itertools::{izip, zip_eq};
use measure_time::print_time;
use serde::{Deserialize, Serialize};

impl SignedMessage {
    pub fn sign<M>(tau: u64, msg: &M, key: &ed25519::Keypair) -> SignedMessage
    where
        M: Serialize,
    {
        print_time!("Signing Message");
        let msg_bytes = bincode::serialize(&(tau, msg)).unwrap();
        let signature = key.sign(&msg_bytes);
        SignedMessage {
            msg_bytes,
            signature,
            signer: key.public,
        }
    }
    pub fn verify<'de, M>(&'de self) -> Result<(u64, M)>
    where
        M: Deserialize<'de>,
    {
        print_time!("Verifying Message");
        self.signer
            .verify_strict(&self.msg_bytes, &self.signature)?;
        bincode::deserialize::<'de, _>(&self.msg_bytes).map_err(|e| e.into()) //TODO: handle error
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignedMessage {
    msg_bytes: Vec<u8>,
    signature: ed25519::Signature,
    pub signer: ed25519::PublicKey,
}
