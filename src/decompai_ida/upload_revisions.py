from dataclasses import dataclass

import anyio
from anyio.abc import ObjectReceiveStream, ObjectSendStream

from decompai_client import Object, PutRevisionBody
from decompai_ida import api, objects, status
from decompai_ida.env import Env

# Max number of revisions to keep in memory before blocking.
# Keep small, this may be large.
_MAX_BUFFERED_REVISIONS = 4


@dataclass(frozen=True)
class Revision:
    addresses: tuple[int, ...]


@dataclass(frozen=True)
class UploadRevisions:
    revisions: tuple[Revision, ...]


@dataclass(frozen=True)
class RevisionUploaded:
    revision: int


async def upload_revisions_task():
    async with Env.get().revisions.subscribe() as input:
        async for upload_revision in input:
            async with anyio.create_task_group() as tg:
                # Small buffer, as each item may be large.
                sender, receiver = anyio.create_memory_object_stream[
                    _RevisionToUpload
                ](_MAX_BUFFERED_REVISIONS)

                tg.start_soon(_read_objects, upload_revision, sender)
                tg.start_soon(_upload_revisions, upload_revision, receiver)


@dataclass(frozen=True)
class _RevisionToUpload:
    objects: tuple[Object, ...]


async def _read_objects(
    upload_revisions: UploadRevisions,
    output: ObjectSendStream[_RevisionToUpload],
):
    env = Env.get()
    total_objects = sum(
        len(revision.addresses) for revision in upload_revisions.revisions
    )

    async with (
        status.begin_task(
            "Decompiling", priority=2, item_count=total_objects
        ) as task,
        output,
    ):
        for i, revision in enumerate(upload_revisions.revisions):
            read_objects = []
            async for result in objects.read_objects(revision.addresses):
                match result:
                    case Object():
                        read_objects.append(result)
                    case objects.ReadFailure():
                        # Don't try processing this again
                        await env.state.mark_addresses_clean((result.address,))
                        print(
                            f"Error reading {result.address:08x}: {result.error}"
                        )

                await task.mark_item_complete()

            await output.send(_RevisionToUpload(objects=tuple(read_objects)))


async def _upload_revisions(
    upload_revisions: UploadRevisions,
    input: ObjectReceiveStream[_RevisionToUpload],
):
    env = Env.get()
    binary_id = await env.state.get_binary_id()

    async with (
        status.begin_task(
            "Uploading", priority=0, item_count=len(upload_revisions.revisions)
        ) as task,
        input,
    ):
        async for revision in input:
            if len(revision.objects) > 0:
                next_revision = (await env.state.get_current_revision()) + 1

                await api.retry_forever(
                    lambda: env.binaries_api.put_revision(
                        binary_id=binary_id,
                        revision_number=next_revision,
                        put_revision_body=PutRevisionBody(
                            objects=list(revision.objects)
                        ),
                    ),
                    task=task,
                )

                await env.state.set_current_revision(next_revision)
                await env.state.mark_addresses_clean(
                    api.parse_address(obj.actual_instance.address)
                    for obj in revision.objects
                    if obj.actual_instance is not None
                )
                await env.uploaded_revisions.post(
                    RevisionUploaded(next_revision)
                )
            await task.mark_item_complete()
