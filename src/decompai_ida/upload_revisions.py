from collections import deque
import typing as ty
from dataclasses import dataclass
from functools import cached_property

import anyio

from decompai_client import Object as ApiObject
from decompai_client import PutRevisionBody
from decompai_ida import api, ida_tasks, logger, objects, state, status
from decompai_ida.async_utils import collect
from decompai_ida.env import Env
from decompai_ida.function_graph import get_funcs_in_approx_topo_order


@dataclass(frozen=True)
class UploadRevisionsOptions:
    max_objects_per_revision: int
    max_revision_bytes: int
    max_pending_revisions: int
    buffer_changes_period: float


@dataclass(frozen=True)
class CheckAddressesForChanges:
    addresses: tuple[int, ...]
    is_initial: bool


@dataclass(frozen=True)
class RevisionUploaded:
    revision: int


async def upload_revisions_task(
    options: UploadRevisionsOptions,
):
    address_queue = _AddressQueue()
    upload_queue = _UploadQueue(
        max_objects_per_revision=options.max_objects_per_revision,
        max_revision_bytes=options.max_revision_bytes,
        max_pending_revisions=options.max_pending_revisions,
    )

    async with anyio.create_task_group() as tg:
        tg.start_soon(
            _push_pending_addresses,
            address_queue,
            options.buffer_changes_period,
        )
        tg.start_soon(_prepare_revisions_task, address_queue, upload_queue)
        tg.start_soon(_upload_revisions_task, upload_queue)


@logger.instrument(task="upload_revisions", subtask="_push_pending_addresses")
async def _push_pending_addresses(
    address_queue: "_AddressQueue",
    buffer_changes_period: float,
):
    env = Env.get()

    async with env.check_addresses.subscribe() as check_addresses_receiver:
        async for message in check_addresses_receiver:
            addresses = list(message.addresses)
            initial = message.is_initial

            with anyio.move_on_after(buffer_changes_period):
                async for message in check_addresses_receiver:
                    addresses.extend(message.addresses)
                    initial = initial or message.is_initial

            async with status.begin_task("local_work"):
                unhandled_addresses = await collect(
                    _read_unhandled_addresses(addresses)
                )
                add_count = await address_queue.push(
                    unhandled_addresses, initial=initial
                )
                await logger.get().adebug(
                    "Pushed addresses to read", count=add_count, initial=initial
                )


@logger.instrument(task="upload_revisions", subtask="prepare_revisions")
async def _prepare_revisions_task(
    address_queue: "_AddressQueue",
    upload_queue: "_UploadQueue",
):
    async with status.begin_task("local_work", start=False) as task:
        while True:
            (
                addresses,
                added_count,
            ) = await address_queue.pop_and_get_added_count(max_addresses=16)

            await task.add_item_count(added_count)

            skipped_objects = list[
                ty.Union[_PendingObject, _UnreadableObject]
            ]()

            async for pending_object in _read_pending_objects(addresses):
                log = logger.get().bind(
                    address=pending_object.address,
                    handles_db_revision=pending_object.handles_db_revision,
                )

                try:
                    # Skip unreadable objects
                    if isinstance(pending_object, _UnreadableObject):
                        await log.awarning(
                            "Can't read object",
                            exc_info=pending_object.error,
                        )
                        skipped_objects.append(pending_object)
                        continue

                    # First, try to update already queued upload.
                    updated_pending = upload_queue.try_updating_pending_object(
                        pending_object
                    )
                    if updated_pending:
                        await log.adebug("Updated pending")
                        continue

                    # Check if current version is same as one previously
                    # uploaded (change didn't affect upload).
                    if pending_object.is_unchanged:
                        await log.adebug("Object unchanged")
                        skipped_objects.append(pending_object)
                        continue

                    await upload_queue.add_object(pending_object)
                    await log.adebug("Object queued")

                except Exception:
                    # Skip this object
                    await log.awarning("Error while handling", exc_info=True)
                    skipped_objects.append(pending_object)
                    pass

                await task.mark_item_complete()

            await ida_tasks.for_each(skipped_objects, _mark_object_handled_sync)

            address_queue_state = await address_queue.get_state()
            if address_queue_state.empty:
                await upload_queue.flush_revision(
                    reason="queue_empty",
                    finishes_initial_analysis=address_queue_state.initial_pushed,
                )
                await task.mark_done()


@logger.instrument(task="upload_revisions", subtask="upload_revisions")
async def _upload_revisions_task(upload_queue: "_UploadQueue"):
    env = Env.get()
    binary_id = await state.get_binary_id()

    while True:
        revision = await upload_queue.wait_for_revision()

        if len(revision.objects) > 0:
            async with status.begin_task("local_work") as task:
                next_revision = (await state.get_current_revision()) + 1

                # Revision considered part of initial analysis if all objects were never uploaded.
                any_updated_object = any(
                    pending_object.was_uploaded
                    for pending_object in revision.objects
                )
                analyze_dependents = (
                    any_updated_object
                    or await state.was_initial_analysis_complete()
                )

                body = PutRevisionBody(
                    objects=[
                        ApiObject(pending_object.object)
                        for pending_object in revision.objects
                    ],
                    analyze_dependents=analyze_dependents,
                )

                await api.retry_forever(
                    lambda: env.binaries_api.put_revision(
                        binary_id=binary_id,
                        revision_number=next_revision,
                        put_revision_body=body,
                    ),
                    task=task,
                    description=f"Put revision {next_revision}",
                )

                await state.set_current_revision(next_revision)
                await ida_tasks.for_each(
                    revision.objects, _mark_object_handled_sync
                )

                await logger.get().ainfo(
                    "Uploaded revision",
                    revision=next_revision,
                    objects=len(revision.objects),
                    finishes_initial_analysis=revision.finishes_initial_analysis,
                    analyze_dependents=analyze_dependents,
                )
                await env.uploaded_revisions.post(
                    RevisionUploaded(revision=next_revision)
                )

        if revision.finishes_initial_analysis:
            await logger.get().ainfo("Marking initial analysis complete")
            await state.mark_initial_analysis_complete()


@dataclass(frozen=True)
class _AddressQueueState:
    empty: bool
    initial_pushed: bool


class _AddressQueue:
    def __init__(self):
        self._added_count = 0
        self._queue = deque[int]()
        self._queue_cond = anyio.Condition()
        self._initial_pushed = False

    async def push(self, addresses: ty.Iterable[int], *, initial: bool) -> int:
        async with self._queue_cond:
            old_len = len(self._queue)
            all_addresses = set(self._queue)
            all_addresses.update(addresses)
            new_len = len(all_addresses)

            self._queue = deque(
                await get_funcs_in_approx_topo_order(all_addresses)
            )
            add_count = new_len - old_len
            self._added_count += add_count
            self._queue_cond.notify_all()

            if initial:
                self._initial_pushed = True

            return add_count

    async def pop_and_get_added_count(
        self, *, max_addresses: int
    ) -> tuple[list[int], int]:
        async with self._queue_cond:
            while len(self._queue) == 0:
                await self._queue_cond.wait()

            items = [
                self._queue.popleft()
                for _ in range(min(max_addresses, len(self._queue)))
            ]
            added_count = self._added_count
            self._added_count = 0

            return items, added_count

    async def get_state(self) -> _AddressQueueState:
        async with self._queue_cond:
            return _AddressQueueState(
                empty=len(self._queue) == 0,
                initial_pushed=self._initial_pushed,
            )


@dataclass(frozen=True)
class _PendingObject:
    handles_db_revision: int
    current_hash: bytes
    uploaded_hash: ty.Optional[bytes]
    object: objects.Object

    @cached_property
    def address(self) -> int:
        return api.parse_address(self.object.address)

    @cached_property
    def size_bytes(self) -> int:
        return len(self.object.model_dump_json().encode("utf-8"))

    @property
    def is_unchanged(self) -> bool:
        return self.current_hash == self.uploaded_hash

    @property
    def was_uploaded(self) -> bool:
        return self.uploaded_hash is not None


@dataclass(frozen=True)
class _UnreadableObject:
    address: int
    handles_db_revision: int
    error: Exception


class _PendingRevision:
    def __init__(self):
        self._objects: dict[int, _PendingObject] = {}
        self._finishes_initial_analysis: bool = False

    def mark_finishes_initial_analysis(self):
        self._finishes_initial_analysis = True

    def as_revision_to_upload(self) -> "_RevisionToUpload":
        return _RevisionToUpload(
            objects=tuple(self._objects.values()),
            finishes_initial_analysis=self._finishes_initial_analysis,
        )

    def try_updating_pending_object(
        self, pending_object: _PendingObject
    ) -> bool:
        if pending_object.address in self._objects:
            self._objects[pending_object.address] = pending_object
            return True
        else:
            return False

    def add_object(self, pending_object: _PendingObject):
        self._objects[pending_object.address] = pending_object

    @property
    def object_count(self) -> int:
        return len(self._objects)

    @property
    def size_bytes(self) -> int:
        return sum(
            pending_object.size_bytes
            for pending_object in self._objects.values()
        )


@dataclass
class _RevisionToUpload:
    objects: tuple[_PendingObject, ...]
    finishes_initial_analysis: bool


class _UploadQueue:
    def __init__(
        self,
        *,
        max_objects_per_revision: int,
        max_revision_bytes: int,
        max_pending_revisions: int,
    ):
        assert (
            # Will deadlock otherwise
            max_pending_revisions >= 1
        )

        self._max_objects_per_revision = max_objects_per_revision
        self._max_revision_bytes = max_revision_bytes
        self._max_pending_revisions = max_pending_revisions

        self._pending_revisions: list[_PendingRevision] = []
        self._staged_revision = _PendingRevision()
        self._push_event = anyio.Event()
        self._pop_revision_event = anyio.Event()

    async def wait_for_revision(self) -> _RevisionToUpload:
        while len(self._pending_revisions) == 0:
            await self._push_event.wait()

        pending_revision = self._pending_revisions.pop(0)
        self._pop_revision_event.set()
        self._pop_revision_event = anyio.Event()

        return pending_revision.as_revision_to_upload()

    async def add_object(self, pending_object: _PendingObject):
        if pending_object.size_bytes > self._max_revision_bytes:
            raise Exception("Object too large to upload")

        if (
            self._staged_revision.size_bytes + pending_object.size_bytes
            > self._max_revision_bytes
        ):
            await self.flush_revision(reason="reached_max_bytes")

        self._staged_revision.add_object(pending_object)

        if self._staged_revision.object_count >= self._max_objects_per_revision:
            await self.flush_revision(reason="reached_max_objects")

    def try_updating_pending_object(
        self, pending_object: _PendingObject
    ) -> bool:
        for pending_revision in (
            self._staged_revision,
            *self._pending_revisions,
        ):
            was_updated = pending_revision.try_updating_pending_object(
                pending_object
            )
            if was_updated:
                return True
        return False

    async def flush_revision(
        self, reason: str, *, finishes_initial_analysis: bool = False
    ):
        while len(self._pending_revisions) >= self._max_pending_revisions:
            await logger.get().ainfo("Too many pending revisions, waiting")
            await self._pop_revision_event.wait()

        await logger.get().ainfo(
            "Flushing revision",
            reason=reason,
            objects=self._staged_revision.object_count,
            bytes=self._staged_revision.size_bytes,
            pending_revisions=len(self._pending_revisions),
            finishes_initial_analysis=finishes_initial_analysis,
        )

        if finishes_initial_analysis:
            self._staged_revision.mark_finishes_initial_analysis()

        self._pending_revisions.append(self._staged_revision)
        self._staged_revision = _PendingRevision()
        self._push_event.set()
        self._push_event = anyio.Event()


@ida_tasks.wrap_generator
def _read_unhandled_addresses(addresses: ty.Iterable[int]):
    for address in addresses:
        sync_status = state.get_sync_status.sync(address)
        if not sync_status.is_handled:
            yield address


@ida_tasks.wrap_generator
def _read_pending_objects(
    addresses: ty.Iterable[int],
) -> ty.Iterator[ty.Union[_UnreadableObject, _PendingObject]]:
    for address in addresses:
        # Read status again on same time as object.
        sync_status = state.get_sync_status.sync(address)

        try:
            obj = objects.read_object.sync(address)
            obj_hash = objects.hash_object.sync(obj)

        except Exception as ex:
            # Skip this version.
            yield _UnreadableObject(
                address=address,
                handles_db_revision=sync_status.db_revision,
                error=ex,
            )
            continue

        yield _PendingObject(
            object=obj,
            current_hash=obj_hash,
            uploaded_hash=sync_status.uploaded_hash,
            handles_db_revision=sync_status.db_revision,
        )


def _mark_object_handled_sync(
    pending_object: ty.Union[_PendingObject, _UnreadableObject],
):
    ida_tasks.assert_running_in_task()
    status = state.get_sync_status.sync(pending_object.address)
    state.set_sync_status.sync(
        pending_object.address,
        status.with_handled_revision(pending_object.handles_db_revision),
    )

    logger.get().debug(
        "Object marked as handled",
        address=pending_object.address,
        current_revision=status.db_revision,
        handled_revision=pending_object.handles_db_revision,
    )
