from typing import Sequence


class Keypair:
    @staticmethod
    def random() -> Keypair:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> PublicKey:
        ...

    def __bytes__(self) -> bytes:
        ...

    public_key: PublicKey


class PublicKey:
    @staticmethod
    def from_bytes(data: bytes) -> PublicKey:
        ...

    def __bytes__(self) -> bytes:
        ...


class Validator:
    ...


class ExternalValidator:

    def __init__(self, address: str, public_key: PublicKey):
        ...


class Transcript:
    ...


class DkgPublicKey:
    ...


class ExternalValidatorMessage:
    ...


class Dkg:

    def __init__(
            self,
            tau: int,
            shares_num: int,
            security_threshold: int,
            validators: Sequence[ExternalValidator],
            me: ExternalValidator,
    ):
        ...

    final_key: DkgPublicKey

    def generate_transcript(self) -> Transcript:
        ...

    def aggregate_transcripts(self, transcripts: Sequence[(ExternalValidator, Transcript)]) -> Transcript:
        ...


class Ciphertext:
    ...


class UnblindingKey:
    ...


class DecryptionShare:
    ...


class AggregatedTranscript:

    def create_decryption_share(
            self,
            dkg: Dkg,
            ciphertext: Ciphertext,
            aad: bytes,
            unblinding_key: UnblindingKey
    ) -> DecryptionShare:
        ...
