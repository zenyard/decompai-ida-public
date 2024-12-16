import typing as ty
from pydantic import TypeAdapter

from netnode import Netnode

from decompai_client import Inference
from decompai_ida import ida_tasks


class State:
    _general: "_Node"

    def __init__(
        self, *, general: "_Node", inferences: "_Node", dirty: "_Node"
    ):
        "Use `get_instance` to create"
        self._general = general
        self._inferences = inferences
        self._dirty = dirty

    @staticmethod
    async def create() -> "State":
        return State(
            general=await _Node.create("decompai"),
            inferences=await _Node.create("decompai.inferences"),
            dirty=await _Node.create("decompai.dirty"),
        )

    async def clear(self):
        await self._general.clear()
        await self._inferences.clear()
        await self._dirty.clear()

    async def try_get_binary_id(self) -> ty.Optional[str]:
        return await self._general.read("binary_id", str)

    async def get_binary_id(self) -> str:
        binary_id = await self.try_get_binary_id()
        if binary_id is None:
            raise Exception("No binary ID")
        return binary_id

    async def set_binary_id(self, binary_id: str):
        def set_if_unset(current: str | None):
            if current is not None:
                raise Exception("Binary ID already set to " + current)
            return binary_id

        return await self._general.modify("binary_id", str, set_if_unset)

    async def get_current_revision(self) -> int:
        "Initially zero"
        return await self._general.read("revision", int) or 0

    async def set_current_revision(self, revision: int):
        await self._general.write("revision", revision)

    async def get_revision_cursor(self) -> ty.Optional[int]:
        return await self._general.read("revision_cursor", int)

    async def set_revision_cursor(self, cursor: int):
        return await self._general.write("revision_cursor", cursor)

    def get_inferences_for_address_sync(self, address: int) -> list[Inference]:
        return self._inferences.read_sync(address, list[Inference]) or []

    def add_inference_for_address_sync(
        self, address: int, inference: Inference
    ):
        self._inferences.modify_sync(
            address,
            list[inference],
            lambda inferences: [*inferences, inference],
            initial=[],
        )

    async def mark_address_dirty(self, address: int):
        await self._dirty.write(address, True)

    @ida_tasks.write
    def mark_addresses_clean(self, addresses: ty.Iterable[int]):
        for address in addresses:
            self._dirty.write_sync(address, False)

    def is_address_dirty_sync(self, address: int) -> bool:
        return self._dirty.read_sync(address, bool, default=True)


_T = ty.TypeVar("_T")
_U = ty.TypeVar("_U")
_Key: ty.TypeAlias = str | int


class _Node:
    """
    Wraps Netnode, allows calling from async code, and validates types with
    Pydantic.
    """

    def __init__(self, inner: Netnode):
        self._inner = inner

    @staticmethod
    async def create(name: str) -> "_Node":
        return _Node(await ida_tasks.run_write(Netnode, f"$ {name}"))

    @ida_tasks.read
    def read(
        self, key: _Key, type_: type[_T], *, default: _U = None
    ) -> _T | _U:
        return self.read_sync(key, type_, default=default)

    def read_sync(
        self, key: _Key, type_: type[_T], *, default: _U = None
    ) -> _T | _U:
        value = self._inner.get(key)
        if value is not None:
            return TypeAdapter(type_).validate_python(value)
        else:
            return default

    @ida_tasks.write
    def write(self, key: _Key, value: ty.Any):
        self.write_sync(key, value)

    def write_sync(self, key: _Key, value: ty.Any):
        self._inner[key] = TypeAdapter(type(value)).dump_python(
            value, mode="json"
        )

    @ida_tasks.write
    def modify(
        self,
        key: _Key,
        type_: ty.Any,
        modifier: ty.Callable[[_T | _U], _T],
        *,
        initial: _U = None,
    ) -> _T:
        return self.modify_sync(key, type_, modifier, initial=initial)

    def modify_sync(
        self,
        key: _Key,
        type_: ty.Any,
        modifier: ty.Callable[[_T | _U], _T],
        *,
        initial: _U = None,
    ) -> _T:
        existing = self._inner.get(key)
        if existing is not None:
            existing = TypeAdapter(type_).validate_python(existing)
        else:
            existing = initial
        modified = modifier(existing)
        self.write_sync(key, modified)
        return modified

    @ida_tasks.write
    def remove(self, key: _Key):
        self.remove_sync(key)

    def remove_sync(self, key: _Key):
        if key in self._inner:
            del self._inner[key]

    @ida_tasks.write
    def clear(self):
        self._inner.kill()
