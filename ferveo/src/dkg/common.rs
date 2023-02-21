use ark_ec::pairing::Pairing;
use ferveo_common::ExternalValidator;

pub fn make_validators<E: Pairing>(
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
