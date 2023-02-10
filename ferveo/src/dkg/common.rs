use std::collections::HashMap;

use anyhow::{anyhow, Result};
use ark_ec::{msm::FixedBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain,
};
use ark_std::{end_timer, start_timer};
use ferveo_common::ExternalValidator;
use ferveo_common::Rng;
use itertools::{izip, zip_eq};
use measure_time::print_time;
use serde::{Deserialize, Serialize};

pub fn make_validators<E: PairingEngine>(
    validators: &[ExternalValidator<E>],
) -> Vec<ferveo_common::Validator<E>> {
    validators
        .iter()
        .enumerate()
        .map(|(index, validator)| ferveo_common::Validator::<E> {
            validator: validator.clone(),
            share_index: index,
        })
        .collect()
}
