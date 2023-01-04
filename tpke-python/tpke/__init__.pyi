class DecryptionShare:
    
    def __bytes__(self) -> bytes:
        ...
    

class ParticipantPayload:

    @staticmethod
    def from_bytes(data: bytes) -> ParticipantPayload:
        ...
    
    def to_decryption_share(self) -> DecryptionShare:
        ...


