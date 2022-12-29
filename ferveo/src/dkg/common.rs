use crate::*;
use ferveo_common::ValidatorSet;
use itertools::izip;

pub fn make_validators<E: PairingEngine>(
    validator_set: ValidatorSet<E>,
) -> Vec<ferveo_common::Validator<E>> {
    validator_set
        .validators
        .iter()
        .enumerate()
        .map(|(index, validator)| ferveo_common::Validator::<E> {
            validator: validator.clone(),
            share_index: index,
        })
        .collect()
}
