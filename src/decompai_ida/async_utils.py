import typing as ty

from anyio.abc import ObjectReceiveStream

_T = ty.TypeVar("_T")


async def wait_for_object_of_type(
    receiver: ObjectReceiveStream, type_: type[_T]
) -> ty.Optional[_T]:
    async for item in receiver:
        if isinstance(item, type_):
            return item
