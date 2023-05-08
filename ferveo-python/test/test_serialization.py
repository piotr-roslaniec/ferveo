from ferveo_py import (
    Keypair,
    Validator,
    Dkg,
    DkgPublicParameters,
    DkgPublicKey
)


def gen_eth_addr(i: int) -> str:
    return f"0x{i:040x}"


tau = 1
security_threshold = 3
shares_num = 4
validator_keypairs = [Keypair.random() for _ in range(shares_num)]
validators = [
    Validator(gen_eth_addr(i), keypair.public_key())
    for i, keypair in enumerate(validator_keypairs)
]
validators.sort(key=lambda v: v.address)


def make_dkg_public_params():
    me = validators[0]
    dkg = Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=security_threshold,
        validators=validators,
        me=me,
    )
    return dkg.public_params


def make_dkg_public_key():
    me = validators[0]
    dkg = Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=security_threshold,
        validators=validators,
        me=me,
    )
    return dkg.public_key


def make_shared_secret():
    # TODO: implement this
    pass


def test_dkg_public_parameters_serialization():
    dkg_public_params = make_dkg_public_params()
    serialized = bytes(dkg_public_params)
    deserialized = DkgPublicParameters.from_bytes(serialized)
    # TODO: Implement comparison
    # assert dkg_public_params == deserialized


# def test_shared_secret_serialization():
#     shared_secret = create_shared_secret_instance()
#     serialized = bytes(shared_secret)
#     deserialized = SharedSecret.from_bytes(serialized)
#     TODO: Implement comparison
#     assert shared_secret == deserialized

def test_keypair_serialization():
    keypair = Keypair.random()
    serialized = bytes(keypair)
    deserialized = Keypair.from_bytes(serialized)
    # TODO: Implement comparison
    # assert keypair == deserialized


def test_dkg_public_key_serialization():
    dkg_pk = make_dkg_public_key()
    serialized = bytes(dkg_pk)
    assert len(serialized) == DkgPublicKey.serialized_size()
