use crate::*;
use ferveo_common::ExternalValidator;
use itertools::izip;

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
