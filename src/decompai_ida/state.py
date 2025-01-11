import typing as ty

import typing_extensions as tye
from netnode import Netnode
from pydantic import BaseModel, TypeAdapter

from decompai_client import Inference
from decompai_ida import ida_tasks
from decompai_ida.env import Env
from decompai_ida.serialization import EncodedBytes


class SyncStatus(BaseModel, frozen=True):
    """
    Attached to every address of object we sync with the server.
    """

    uploaded_hash: ty.Optional[EncodedBytes]
    """
    Hash of the uploaded object. If `None` means not uploaded.
    """

    db_revision: int
    """
    Incremented as soon as possible on every suspected change in the database,
    even if the change may turn up to be not meaningful for us.
    """

    handled_revision: int
    """
    Incremented to match the `db_revision` we know to have been completely
    handled by the plugin - either by uploading or deciding to skip it.
    """

    @property
    def is_handled(self) -> bool:
        return self.db_revision == self.handled_revision

    def with_incremented_db_revision(self) -> "SyncStatus":
        return SyncStatus(
            uploaded_hash=self.uploaded_hash,
            db_revision=self.db_revision + 1,
            handled_revision=self.handled_revision,
        )

    def with_handled_revision(self, handled_revision: int) -> "SyncStatus":
        return SyncStatus(
            uploaded_hash=self.uploaded_hash,
            db_revision=self.db_revision,
            handled_revision=max(self.handled_revision, handled_revision),
        )

    def with_uploaded_hash(self, uploaded_hash: bytes) -> "SyncStatus":
        return SyncStatus(
            uploaded_hash=uploaded_hash,
            db_revision=self.db_revision,
            handled_revision=self.handled_revision,
        )

    def as_fully_handled(self) -> "SyncStatus":
        return SyncStatus(
            uploaded_hash=self.uploaded_hash,
            db_revision=self.db_revision,
            handled_revision=self.db_revision,
        )


_INITIAL_SYNC_STATUS = SyncStatus(
    uploaded_hash=None, db_revision=1, handled_revision=0
)


@ida_tasks.wrap
def clear():
    nodes = Env.get().state_nodes
    nodes.general.clear()
    nodes.inferences.clear()
    nodes.dirty.clear()
    nodes.sync_status.clear()


@ida_tasks.wrap
def get_user_confirmation() -> ty.Optional[bool]:
    nodes = Env.get().state_nodes
    return nodes.general.read_sync("user_confirmed", bool)


@ida_tasks.wrap
def set_user_confirmation(value: bool):
    nodes = Env.get().state_nodes
    return nodes.general.write_sync("user_confirmed", value)


@ida_tasks.wrap
def try_get_binary_id() -> ty.Optional[str]:
    nodes = Env.get().state_nodes
    return nodes.general.read_sync("binary_id", str)


@ida_tasks.wrap
def get_binary_id() -> str:
    binary_id = try_get_binary_id.sync()
    if binary_id is None:
        raise Exception("No binary ID")
    return binary_id


@ida_tasks.wrap
def set_binary_id(binary_id: str):
    nodes = Env.get().state_nodes

    def set_if_unset(current: ty.Optional[str]):
        if current is not None:
            raise Exception("Binary ID already set to " + current)
        return binary_id

    return nodes.general.modify_sync("binary_id", str, set_if_unset)


@ida_tasks.wrap
def get_current_revision() -> int:
    nodes = Env.get().state_nodes
    "Initially zero"
    return nodes.general.read_sync("revision", int) or 0


@ida_tasks.wrap
def set_current_revision(revision: int):
    nodes = Env.get().state_nodes
    nodes.general.write_sync("revision", revision)


@ida_tasks.wrap
def get_revision_cursor() -> ty.Optional[int]:
    nodes = Env.get().state_nodes
    return nodes.general.read_sync("revision_cursor", int)


@ida_tasks.wrap
def set_revision_cursor(cursor: int):
    nodes = Env.get().state_nodes
    return nodes.general.write_sync("revision_cursor", cursor)


@ida_tasks.wrap
def get_inferences_for_address(address: int) -> list[Inference]:
    nodes = Env.get().state_nodes
    return nodes.inferences.read_sync(address, list[Inference]) or []


@ida_tasks.wrap
def add_inference_for_address(address: int, inference: Inference):
    nodes = Env.get().state_nodes
    nodes.inferences.modify_sync(
        address,
        list[inference],
        lambda inferences: [*inferences, inference],
        initial=[],
    )


@ida_tasks.wrap
def get_sync_status(address: int) -> SyncStatus:
    nodes = Env.get().state_nodes
    return nodes.sync_status.read_sync(
        address, SyncStatus, default=_INITIAL_SYNC_STATUS
    )


@ida_tasks.wrap
def set_sync_status(address: int, sync_status: SyncStatus):
    nodes = Env.get().state_nodes
    nodes.sync_status.write_sync(address, sync_status)


class StateNodes:
    def __init__(self):
        "Use `get_instance` to create"
        self.general = _Node("decompai")
        self.inferences = _Node("decompai.inferences")
        self.dirty = _Node("decompai.dirty")
        self.sync_status = _Node("decompai.sync_status")


_T = ty.TypeVar("_T")
_U = ty.TypeVar("_U")
_Key: tye.TypeAlias = ty.Union[str, int]


class _Node:
    """
    Wraps Netnode, validates types with Pydantic.
    """

    def __init__(self, name: str):
        self._inner = Netnode(f"$ {name}")

    def read_sync(
        self, key: _Key, type_: type[_T], *, default: _U = None
    ) -> ty.Union[_T, _U]:
        value = self._inner.get(key)
        if value is not None:
            return TypeAdapter(type_).validate_python(value)
        else:
            return default

    def write_sync(self, key: _Key, value: ty.Any):
        self._inner[key] = TypeAdapter(type(value)).dump_python(
            value, mode="json"
        )

    def modify_sync(
        self,
        key: _Key,
        type_: ty.Any,
        modifier: ty.Callable[[ty.Union[_T, _U]], _T],
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

    def remove(self, key: _Key):
        if key in self._inner:
            del self._inner[key]

    def clear(self):
        self._inner.kill()
