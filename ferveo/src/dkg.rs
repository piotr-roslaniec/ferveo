#![allow(clippy::many_single_char_names)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use anyhow::anyhow;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::Zero;
use ark_ff::{Field, One};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain, Polynomial,
};
use ark_serialize::*;
use bincode::Options;
use ed25519_dalek as ed25519;

pub mod common;
pub mod pv;

pub use common::*;
pub use pv::*;

// DKG parameters
#[derive(Copy, Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Params {
    // TODO: Rename to ritual_id?
    pub tau: u64,
    pub security_threshold: u32,
    pub shares_num: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PvssScheduler {
    Wait,
    Issue,
}

#[derive(Debug, Clone)]
pub enum DkgState<E: PairingEngine> {
    Sharing { accumulated_shares: u32, block: u32 },
    Dealt,
    Success { final_key: E::G1Affine },
    Invalid,
}

impl<E: PairingEngine> CanonicalSerialize for DkgState<E> {
    #[inline]
    fn serialize<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), SerializationError> {
        match self {
            Self::Sharing {
                accumulated_shares,
                block,
            } => {
                CanonicalSerialize::serialize(&0u8, &mut writer)?;
                CanonicalSerialize::serialize(
                    &(*accumulated_shares, *block),
                    &mut writer,
                )
            }
            Self::Dealt => CanonicalSerialize::serialize(&1u8, &mut writer),
            Self::Success { final_key } => {
                CanonicalSerialize::serialize(&2u8, &mut writer)?;
                final_key.serialize(&mut writer)
            }
            Self::Invalid => CanonicalSerialize::serialize(&3u8, &mut writer),
        }
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        match self {
            Self::Sharing {
                accumulated_shares,
                block,
            } => {
                0u8.serialized_size()
                    + (*accumulated_shares, *block).serialized_size()
            }
            Self::Dealt => 1u8.serialized_size(),
            Self::Success { final_key } => {
                2u8.serialized_size() + final_key.serialized_size()
            }
            Self::Invalid => 3u8.serialized_size(),
        }
    }
}

impl<E: PairingEngine> CanonicalDeserialize for DkgState<E> {
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let variant = <u8 as CanonicalDeserialize>::deserialize(&mut reader)?;
        match variant {
            0 => {
                let (accumulated_shares, block) =
                    <(u32, u32) as CanonicalDeserialize>::deserialize(
                        &mut reader,
                    )?;
                Ok(Self::Sharing {
                    accumulated_shares,
                    block,
                })
            }
            1 => Ok(Self::Dealt),
            2 => Ok(Self::Success {
                final_key: <E as PairingEngine>::G1Affine::deserialize(
                    &mut reader,
                )?,
            }),
            3 => Ok(Self::Invalid),
            _ => Err(SerializationError::InvalidData),
        }
    }
}
