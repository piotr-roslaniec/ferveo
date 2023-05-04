use std::{cmp::Ordering, fmt::Display, str::FromStr};

use ark_ec::pairing::Pairing;
use ferveo_common::PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(
    Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize, Hash,
)]
pub struct EthereumAddress(String);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EthereumAddressParseError {
    #[error("Invalid Ethereum address length.")]
    InvalidLength,

    #[error("Invalid hex value in Ethereum address.")]
    InvalidHex,
}

impl FromStr for EthereumAddress {
    type Err = EthereumAddressParseError;

    fn from_str(s: &str) -> Result<EthereumAddress, EthereumAddressParseError> {
        if s.len() != 42 {
            return Err(EthereumAddressParseError::InvalidLength);
        }
        hex::decode(&s[2..])
            .map_err(|_| EthereumAddressParseError::InvalidHex)?;
        Ok(EthereumAddress(s.to_string()))
    }
}

impl Display for EthereumAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Represents an external validator
pub struct Validator<E: Pairing> {
    /// The established address of the validator
    pub address: EthereumAddress,
    /// The Public key
    pub public_key: PublicKey<E>,
}

impl<E: Pairing> PartialOrd for Validator<E> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

impl<E: Pairing> Ord for Validator<E> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.address.cmp(&other.address)
    }
}

impl<E: Pairing> Validator<E> {
    pub fn new(
        address: String,
        public_key: PublicKey<E>,
    ) -> Result<Self, EthereumAddressParseError> {
        Ok(Self {
            address: EthereumAddress::from_str(&address)?,
            public_key,
        })
    }
}
