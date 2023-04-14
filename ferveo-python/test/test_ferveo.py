import pytest

from ferveo_py import (
    encrypt,
    combine_decryption_shares_simple,
    combine_decryption_shares_precomputed,
    decrypt_with_shared_secret,
    Keypair,
    PublicKey,
    ExternalValidator,
    Transcript,
    Dkg,
    Ciphertext,
    UnblindingKey,
    DecryptionShareSimple,
    DecryptionSharePrecomputed,
    AggregatedTranscript,
    DkgPublicKey,
    DkgPublicParameters,
    SharedSecret,
)


def decryption_share_for_variant(variant, agg_transcript):
    if variant == "simple":
        return agg_transcript.create_decryption_share_simple
    elif variant == "precomputed":
        return agg_transcript.create_decryption_share_precomputed
    else:
        raise ValueError("Unknown variant")


def combine_shares_for_variant(variant):
    if variant == "simple":
        return combine_decryption_shares_simple
    elif variant == "precomputed":
        return combine_decryption_shares_precomputed
    else:
        raise ValueError("Unknown variant")


def scenario_for_variant(variant, shares_num=4, security_threshold=3):
    if variant not in ["simple", "precomputed"]:
        raise ValueError("Unknown variant: " + variant)

    tau = 1
    validator_keypairs = [Keypair.random() for _ in range(0, shares_num)]
    validators = [
        ExternalValidator(f"validator-{i}", keypair.public_key)
        for i, keypair in enumerate(validator_keypairs)
    ]
    messages = []
    for sender in validators:
        dkg = Dkg(
            tau=tau,
            shares_num=shares_num,
            security_threshold=security_threshold,
            validators=validators,
            me=sender,
        )
        messages.append((sender, dkg.generate_transcript()))
    me = validators[0]
    dkg = Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=security_threshold,
        validators=validators,
        me=me,
    )
    pvss_aggregated = dkg.aggregate_transcripts(messages)
    assert pvss_aggregated.validate(dkg)
    msg = "abc".encode()
    aad = "my-aad".encode()
    ciphertext = encrypt(msg, aad, dkg.final_key)
    decryption_shares = []
    for validator, validator_keypair in zip(validators, validator_keypairs):
        dkg = Dkg(
            tau=tau,
            shares_num=shares_num,
            security_threshold=security_threshold,
            validators=validators,
            me=validator,
        )
        agg_transcript_deser = AggregatedTranscript.from_bytes(bytes(pvss_aggregated))
        agg_transcript_deser.validate(dkg)

        decryption_share = decryption_share_for_variant('simple', agg_transcript_deser)(
            dkg, ciphertext, aad, validator_keypair
        )
        decryption_shares.append(decryption_share)
    shared_secret = combine_shares_for_variant('simple')(decryption_shares, dkg.public_params)
    plaintext = decrypt_with_shared_secret(ciphertext, aad, shared_secret, dkg.public_params)
    assert bytes(plaintext) == msg


def test_tdec_workflow_for_simple_variant():
    # nr of shares must be a multiple of 2
    for shares_num in [2, 4, 8]:
        for security_threshold in range(2, shares_num + 2, 4):
            scenario_for_variant("simple", shares_num, security_threshold)


def test_tdec_workflow_for_precomputed_variant():
    # nr of shares must be a multiple of 2
    for shares_num in [2, 4, 8]:
        for security_threshold in range(2, shares_num + 2, 4):
            scenario_for_variant("precomputed", shares_num, security_threshold)


if __name__ == "__main__":
    pytest.main(["-v", "-k", "test_ferveo"])
