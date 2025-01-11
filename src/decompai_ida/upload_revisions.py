import typing as ty
from dataclasses import dataclass
from functools import cached_property

import anyio

from decompai_client import Object as ApiObject
from decompai_client import PutRevisionBody
from decompai_ida import api, ida_tasks, objects, state, status
from decompai_ida.async_utils import collect
from decompai_ida.env import Env
from decompai_ida.function_graph import get_funcs_in_approx_topo_order


@dataclass(frozen=True)
class UploadRevisionsOptions:
    objects_per_revision: int
    buffer_changes_period: float


@dataclass(frozen=True)
class CheckAddressesForChanges:
    addresses: tuple[int, ...]


@dataclass(frozen=True)
class RevisionUploaded:
    revision: int


async def upload_revisions_task(
    options: UploadRevisionsOptions,
):
    upload_queue = _UploadQueue(
        objects_per_revision=options.objects_per_revision,
    )

    async with anyio.create_task_group() as tg:
        tg.start_soon(
            _prepare_revisions_task, upload_queue, options.buffer_changes_period
        )
        tg.start_soon(_upload_revisions_task, upload_queue)


async def _prepare_revisions_task(
    upload_queue: "_UploadQueue",
    buffer_changes_period: float,
):
    env = Env.get()

    async with env.check_addresses.subscribe() as check_addresses_receiver:
        async for message in check_addresses_receiver:
            addresses = list(message.addresses)

            with anyio.move_on_after(buffer_changes_period):
                async for message in check_addresses_receiver:
                    addresses.extend(message.addresses)

            unhandled_addresses = await collect(
                _read_unhandled_addresses(addresses)
            )

            if len(unhandled_addresses) == 0:
                continue

            async with status.begin_task("local_work") as task:
                unhandled_addresses = await get_funcs_in_approx_topo_order(
                    unhandled_addresses
                )

                # Read objects into queue. This may take long time.
                await task.set_item_count(len(unhandled_addresses))
                unchanged_objects = list[_PendingObject]()

                async for (
                    pending_object
                ) in _read_pending_objects_skipping_unreadable(
                    unhandled_addresses
                ):
                    # First, try to update already queued upload.
                    updated_pending = upload_queue.try_updating_pending_object(
                        pending_object
                    )

                    if updated_pending:
                        continue

                    # Check if current version is same as one previously
                    # uploaded (change didn't affect upload).
                    if pending_object.is_unchanged:
                        unchanged_objects.append(pending_object)
                        continue

                    upload_queue.add_object(pending_object)
                    await task.mark_item_complete()

                upload_queue.flush_revision()
                await ida_tasks.for_each(
                    unchanged_objects, _mark_object_uploaded_sync
                )


async def _upload_revisions_task(upload_queue: "_UploadQueue"):
    env = Env.get()
    binary_id = await state.get_binary_id()

    while True:
        revision = await upload_queue.wait_for_revision()

        async with status.begin_task("local_work") as task:
            next_revision = (await state.get_current_revision()) + 1

            body = PutRevisionBody(
                objects=[
                    ApiObject(pending_object.object)
                    for pending_object in revision
                ]
            )

            await api.retry_forever(
                lambda: env.binaries_api.put_revision(
                    binary_id=binary_id,
                    revision_number=next_revision,
                    put_revision_body=body,
                ),
                task=task,
            )

            await state.set_current_revision(next_revision)
            await ida_tasks.for_each(revision, _mark_object_uploaded_sync)
            await env.uploaded_revisions.post(
                RevisionUploaded(revision=next_revision)
            )


@dataclass
class _PendingObject:
    handles_db_revision: int
    current_hash: bytes
    uploaded_hash: ty.Optional[bytes]
    object: objects.Object

    @cached_property
    def address(self) -> int:
        return api.parse_address(self.object.address)

    @property
    def is_unchanged(self) -> bool:
        return self.current_hash == self.uploaded_hash


class _UploadQueue:
    def __init__(self, *, objects_per_revision: int):
        self._objects_per_revision = objects_per_revision

        self._pending_revisions: list[dict[int, _PendingObject]] = []
        self._staged_revision: dict[int, _PendingObject] = {}
        self._push_event = anyio.Event()

    async def wait_for_revision(
        self,
    ) -> tuple[_PendingObject, ...]:
        while len(self._pending_revisions) == 0:
            await self._push_event.wait()

        pending_revision = self._pending_revisions.pop(0)
        return tuple(pending_revision.values())

    def add_object(self, pending_object: _PendingObject):
        updated = self.try_updating_pending_object(pending_object)
        if updated:
            return

        # Otherwise add to staged revision.
        self._staged_revision[pending_object.address] = pending_object

        if len(self._staged_revision) == self._objects_per_revision:
            self.flush_revision()

    def try_updating_pending_object(
        self, pending_object: _PendingObject
    ) -> bool:
        for pending_revision in (
            self._staged_revision,
            *self._pending_revisions,
        ):
            if pending_object.address in pending_revision:
                pending_revision[pending_object.address] = pending_object
                return True
        return False

    def flush_revision(self):
        if len(self._staged_revision) == 0:
            return

        self._pending_revisions.append(self._staged_revision)
        self._staged_revision = {}
        self._push_event.set()
        self._push_event = anyio.Event()


@ida_tasks.wrap_generator
def _read_unhandled_addresses(addresses: ty.Iterable[int]):
    for address in addresses:
        sync_status = state.get_sync_status.sync(address)
        if not sync_status.is_handled:
            yield address


@ida_tasks.wrap_generator
def _read_pending_objects_skipping_unreadable(addresses: ty.Iterable[int]):
    for address in addresses:
        # Run status again on same time as object.
        sync_status = state.get_sync_status.sync(address)

        try:
            read_obj = objects.read_object.sync(address)

        except Exception:
            # Skip this version.
            state.set_sync_status.sync(
                address,
                sync_status.as_fully_handled(),
            )
            continue

        yield _PendingObject(
            object=read_obj.object,
            current_hash=read_obj.hash,
            uploaded_hash=sync_status.uploaded_hash,
            handles_db_revision=sync_status.db_revision,
        )


def _mark_object_uploaded_sync(pending_object: _PendingObject):
    new_status = (
        state.get_sync_status.sync(pending_object.address)
        .with_uploaded_hash(pending_object.current_hash)
        .with_handled_revision(pending_object.handles_db_revision)
    )

    state.set_sync_status.sync(pending_object.address, new_status)
