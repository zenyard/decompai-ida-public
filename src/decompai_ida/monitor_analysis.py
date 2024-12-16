import typing as ty
from dataclasses import dataclass

import anyio
from anyio.abc import ObjectReceiveStream, ObjectSendStream

from decompai_client import BinaryAnalysisIdle, BinaryAnalysisInProgress
from decompai_ida import api, status
from decompai_ida.inferences import apply_inferences
from decompai_ida.env import Env
from decompai_ida.upload_revisions import RevisionUploaded

_SERVER_POLL_INTERVAL = 1


@dataclass(frozen=True, kw_only=True)
class _ServerStateChanged:
    # Server revision - done plus progress on current.
    revision_progress: float


_Message: ty.TypeAlias = RevisionUploaded | _ServerStateChanged


async def monitor_analysis():
    sender, receiver = anyio.create_memory_object_stream(128)

    async with anyio.create_task_group() as tg:
        tg.start_soon(_poll_server, sender)
        tg.start_soon(_push_uploaded_revisions, sender)
        tg.start_soon(_update_analysis_state, receiver)


async def _poll_server(sender: ObjectSendStream[_Message]):
    env = Env.get()
    binary_id = await env.state.get_binary_id()

    async with status.begin_task("Connecting", start=False) as task:
        while True:
            await anyio.sleep(_SERVER_POLL_INTERVAL)

            try:
                revision = await env.state.get_current_revision()
                response = await env.binaries_api.get_status(
                    binary_id=binary_id
                )

                await _poll_inferences()

                match response.actual_instance:
                    case BinaryAnalysisIdle():
                        progress = 1.0
                    case BinaryAnalysisInProgress() as in_progress:
                        progress = in_progress.progress
                    case _:
                        raise Exception(
                            f"Unknown status: {response.actual_instance}"
                        )

                await sender.send(
                    _ServerStateChanged(
                        revision_progress=revision - 1.0 + progress
                    )
                )

                await task.mark_done()

            except Exception as ex:
                if api.is_temporary_error(ex):
                    await task.set_warning("Can't reach server")
                else:
                    raise


async def _push_uploaded_revisions(sender: ObjectSendStream[_Message]):
    env = Env.get()

    async with env.uploaded_revisions.subscribe() as upload_revisions:
        async for uploaded_revision in upload_revisions:
            await sender.send(uploaded_revision)


async def _update_analysis_state(receiver: ObjectReceiveStream[_Message]):
    # Revision which current progress started showing.
    base_revision = None
    # Revision which current analysis is expected to end.
    target_revision = await Env.get().state.get_current_revision()
    # Current server fractional revision (done plus progress on current).
    server_progress = 0.0

    async with (
        status.begin_task("Analyzing", priority=1, start=False) as task,
        receiver,
    ):
        async for update in receiver:
            match update:
                case RevisionUploaded():
                    target_revision = update.revision
                case _ServerStateChanged():
                    server_progress = update.revision_progress

            if server_progress >= target_revision:
                base_revision = None
                await task.mark_done()
                continue

            if base_revision is None:
                base_revision = int(server_progress)

            await task.set_progress(
                (server_progress - base_revision)
                / (target_revision - base_revision)
            )


async def _poll_inferences():
    env = Env.get()
    binary_id = await env.state.get_binary_id()
    cursor = await env.state.get_revision_cursor()
    current_revision = await env.state.get_current_revision()

    while True:
        if current_revision is None:
            break

        result = await env.binaries_api.get_inferences(
            binary_id=binary_id,
            revision_number=current_revision,
            cursor=cursor,
        )

        if len(result.inferences) > 0:
            await apply_inferences(result.inferences)

        cursor = result.cursor
        await env.state.set_revision_cursor(cursor)

        if not result.has_next:
            break
