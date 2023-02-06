from ferveo import (
    encrypt,
    combine_decryption_shares,
    decrypt_with_shared_secret,
    Keypair,
    PublicKey,
    ExternalValidator,
    Transcript,
    Dkg,
    Ciphertext,
    UnblindingKey,
    DecryptionShare,
    AggregatedTranscript,
)

tau = 1
security_threshold = 3
shares_num = 4
validator_keypairs = [Keypair.random() for _ in range(0, shares_num)]
validators = [
    ExternalValidator(f"validator-{i}", keypair.public_key)
    for i, keypair in enumerate(validator_keypairs)
]
me = validators[0]

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
    aggregate = dkg.aggregate_transcripts(messages)
    assert pvss_aggregated.validate(dkg)
    decryption_share = aggregate.create_decryption_share(
        dkg, ciphertext, aad, validator_keypair
    )
    decryption_shares.append(decryption_share)

shared_secret = combine_decryption_shares(decryption_shares)

plaintext = decrypt_with_shared_secret(ciphertext, aad, shared_secret)
assert bytes(plaintext) == msg
