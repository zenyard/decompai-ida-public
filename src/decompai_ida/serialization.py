import base64
import typing as ty

import typing_extensions as tye
from pydantic import BeforeValidator, PlainSerializer


def _encode_bytes(data: bytes) -> str:
    return base64.b85encode(data).decode("ascii")


def _decode_bytes(data: ty.Any) -> bytes:
    if isinstance(data, str):
        data = base64.b85decode(data)
    return data


EncodedBytes: tye.TypeAlias = ty.Annotated[
    bytes,
    PlainSerializer(_encode_bytes),
    BeforeValidator(_decode_bytes),
]
"""
`bytes` that are efficiently encoded using base85.
"""
