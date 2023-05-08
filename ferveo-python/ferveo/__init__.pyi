from typing import Sequence


class Keypair:
    @staticmethod
    def random() -> Keypair:
        ...

    @staticmethod
    def from_secure_randomness(data: bytes) -> Keypair:
        ...

    @staticmethod
    def secure_randomness_size(data: bytes) -> int:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> Keypair:
        ...

    def __bytes__(self) -> bytes:
        ...

    def public_key(self) -> PublicKey:
        ...


class PublicKey:
    @staticmethod
    def from_bytes(data: bytes) -> PublicKey:
        ...

    def __bytes__(self) -> bytes:
        ...


class Validator:

    def __init__(self, address: str, public_key: PublicKey):
        ...

    address: str

    public_key: PublicKey


class Transcript:
    @staticmethod
    def from_bytes(data: bytes) -> Transcript:
        ...

    def __bytes__(self) -> bytes:
        ...


class DkgPublicKey:
    @staticmethod
    def from_bytes(data: bytes) -> DkgPublicKey:
        ...

    def __bytes__(self) -> bytes:
        ...


class Dkg:

    def __init__(
            self,
            tau: int,
            shares_num: int,
            security_threshold: int,
            validators: Sequence[Validator],
            me: Validator,
    ):
        ...

    public_key: DkgPublicKey

    public_params: DkgPublicParameters

    def generate_transcript(self) -> Transcript:
        ...

    def aggregate_transcripts(self, messages: Sequence[(Validator, Transcript)]) -> AggregatedTranscript:
        ...


class Ciphertext:
    @staticmethod
    def from_bytes(data: bytes) -> Ciphertext:
        ...

    def __bytes__(self) -> bytes:
        ...


class DecryptionShareSimple:
    @staticmethod
    def from_bytes(data: bytes) -> DecryptionShareSimple:
        ...

    def __bytes__(self) -> bytes:
        ...


class DecryptionSharePrecomputed:
    @staticmethod
    def from_bytes(data: bytes) -> DecryptionSharePrecomputed:
        ...

    def __bytes__(self) -> bytes:
        ...


class DkgPublicParameters:
    @staticmethod
    def from_bytes(data: bytes) -> DkgPublicParameters:
        ...

    def __bytes__(self) -> bytes:
        ...


class AggregatedTranscript:

    def __init__(self, messages: Sequence[(Validator, Transcript)]):
        ...

    def verify(self, shares_num: int, messages: Sequence[(Validator, Transcript)]) -> bool:
        ...

    def create_decryption_share_simple(
            self,
            dkg: Dkg,
            ciphertext: Ciphertext,
            aad: bytes,
            validator_keypair: Keypair
    ) -> DecryptionShareSimple:
        ...

    def create_decryption_share_precomputed(
            self,
            dkg: Dkg,
            ciphertext: Ciphertext,
            aad: bytes,
            validator_keypair: Keypair
    ) -> DecryptionSharePrecomputed:
        ...


    @staticmethod
    def from_bytes(data: bytes) -> AggregatedTranscript:
        ...

    def __bytes__(self) -> bytes:
        ...


class SharedSecret:

    @staticmethod
    def from_bytes(data: bytes) -> SharedSecret:
        ...

    def __bytes__(self) -> bytes:
        ...


def encrypt(message: bytes, add: bytes, dkg_public_key: DkgPublicKey) -> Ciphertext:
    ...


def combine_decryption_shares_simple(
        decryption_shares: Sequence[DecryptionShareSimple],
        dkg_public_params: DkgPublicParameters,
) -> bytes:
    ...


def combine_decryption_shares_precomputed(
        decryption_shares: Sequence[DecryptionSharePrecomputed],
) -> SharedSecret:
    ...


def decrypt_with_shared_secret(
        ciphertext: Ciphertext,
        aad: bytes,
        shared_secret: SharedSecret,
        dkg_params: DkgPublicParameters,
) -> bytes:
    ...
