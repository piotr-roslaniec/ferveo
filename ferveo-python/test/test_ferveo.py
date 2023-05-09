import pytest

from ferveo_py import (
    encrypt,
    combine_decryption_shares_simple,
    combine_decryption_shares_precomputed,
    decrypt_with_shared_secret,
    Keypair,
    Validator,
    Dkg,
    AggregatedTranscript,
    DkgPublicKey
)


def gen_eth_addr(i: int) -> str:
    return f"0x{i:040x}"


def decryption_share_for_variant(variant, agg_transcript):
    if variant == "simple":
        return agg_transcript.create_decryption_share_simple
    elif variant == "precomputed":
        return agg_transcript.create_decryption_share_precomputed
    else:
        raise ValueError("Unknown variant")


def combine_shares_for_variant(variant, decryption_shares):
    if variant == "simple":
        return combine_decryption_shares_simple(decryption_shares)
    elif variant == "precomputed":
        return combine_decryption_shares_precomputed(decryption_shares)
    else:
        raise ValueError("Unknown variant")


def scenario_for_variant(variant, shares_num, threshold, shares_to_use):
    if variant not in ["simple", "precomputed"]:
        raise ValueError("Unknown variant: " + variant)

    tau = 1
    validator_keypairs = [Keypair.random() for _ in range(0, shares_num)]
    validators = [
        Validator(gen_eth_addr(i), keypair.public_key())
        for i, keypair in enumerate(validator_keypairs)
    ]
    validators.sort(key=lambda v: v.address)

    messages = []
    for sender in validators:
        dkg = Dkg(
            tau=tau,
            shares_num=shares_num,
            security_threshold=threshold,
            validators=validators,
            me=sender,
        )
        messages.append((sender, dkg.generate_transcript()))

    dkg = Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=threshold,
        validators=validators,
        me=validators[0],
    )
    pvss_aggregated = dkg.aggregate_transcripts(messages)
    assert pvss_aggregated.verify(shares_num, messages)

    dkg_pk_bytes = bytes(dkg.public_key)
    dkg_pk = DkgPublicKey.from_bytes(dkg_pk_bytes)

    msg = "abc".encode()
    aad = "my-aad".encode()
    ciphertext = encrypt(msg, aad, dkg_pk)

    decryption_shares = []
    for validator, validator_keypair in zip(validators, validator_keypairs):
        dkg = Dkg(
            tau=tau,
            shares_num=shares_num,
            security_threshold=threshold,
            validators=validators,
            me=validator,
        )
        pvss_aggregated = dkg.aggregate_transcripts(messages)
        assert pvss_aggregated.verify(shares_num, messages)

        decryption_share = decryption_share_for_variant(variant, pvss_aggregated)(
            dkg, ciphertext, aad, validator_keypair
        )
        decryption_shares.append(decryption_share)

    decryption_shares = decryption_shares[:shares_to_use]

    shared_secret = combine_shares_for_variant(variant, decryption_shares)

    if variant == "simple" and len(decryption_shares) < threshold:
        with pytest.raises(ValueError):
            decrypt_with_shared_secret(ciphertext, aad, shared_secret, dkg.public_params)
        return

    if variant == "precomputed" and len(decryption_shares) < shares_num:
        with pytest.raises(ValueError):
            decrypt_with_shared_secret(ciphertext, aad, shared_secret, dkg.public_params)
        return

    plaintext = decrypt_with_shared_secret(ciphertext, aad, shared_secret, dkg.public_params)
    assert bytes(plaintext) == msg


def test_simple_tdec_has_enough_messages():
    scenario_for_variant("simple", shares_num=4, threshold=3, shares_to_use=3)


def test_simple_tdec_doesnt_have_enough_messages():
    scenario_for_variant("simple", shares_num=4, threshold=3, shares_to_use=2)


def test_precomputed_tdec_has_enough_messages():
    scenario_for_variant("precomputed", shares_num=4, threshold=4, shares_to_use=4)


def test_precomputed_tdec_doesnt_have_enough_messages():
    scenario_for_variant("precomputed", shares_num=4, threshold=4, shares_to_use=3)


PARAMS = [
    (1, 'simple'),
    (4, 'simple'),
    (8, 'simple'),
    (32, 'simple'),
    (1, 'precomputed'),
    (4, 'precomputed'),
    (8, 'precomputed'),
    (32, 'precomputed'),

]

TEST_CASES_WITH_THRESHOLD_RANGE = []
for (shares_num, variant) in PARAMS:
    for threshold in range(1, shares_num):
        TEST_CASES_WITH_THRESHOLD_RANGE.append((variant, shares_num, threshold))


# Avoid running this test case as it takes a long time
# @pytest.mark.parametrize("variant, shares_num, threshold", TEST_CASES_WITH_THRESHOLD_RANGE)
# def test_reproduce_nucypher_issue(variant, shares_num, threshold):
#     scenario_for_variant(variant, shares_num, threshold, shares_to_use=threshold)


if __name__ == "__main__":
    pytest.main(["-v", "-k", "test_ferveo"])
