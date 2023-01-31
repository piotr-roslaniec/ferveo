from typing import Sequence


class ExternalValidator:

    # TODO: Add a proper constructor. Currently, breaks `pip install`.
    def __init__(self):
        ...


class PubliclyVerifiableDkg:

    def __init__(
            self,
            validators: Sequence[ExternalValidator],
            me: ExternalValidator,
            threshold: int,
            shares_num: int,
    ):
        ...


