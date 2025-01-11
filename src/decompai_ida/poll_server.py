import typing as ty
from dataclasses import dataclass

import anyio

from decompai_client import BinaryAnalysisIdle, BinaryAnalysisInProgress
from decompai_ida import api, inferences, state, status
from decompai_ida.env import Env

_POLL_INTERVAL = 1


@dataclass(frozen=True)
class ServerStateChanged:
    # Server revision - done plus progress on current.
    revision_progress: float


async def poll_server_task():
    env = Env.get()

    async with env.uploaded_revisions.subscribe() as uploaded_revisions:
        while True:
            await _poll_server()

            # Restart after next upload
            await uploaded_revisions.receive()


async def _poll_server():
    async with status.begin_task("remote_work", start=False) as task:
        while True:
            try:
                result = await _poll_server_once()
                await task.mark_done()

                if result == "stop":
                    break

            except Exception as ex:
                if api.is_temporary_error(ex):
                    await task.set_warning()
                else:
                    raise

            await anyio.sleep(_POLL_INTERVAL)


async def _poll_server_once() -> ty.Literal["stop", "continue_polling"]:
    env = Env.get()
    binary_id = await state.get_binary_id()

    revision = await state.get_current_revision()
    response = await env.binaries_api.get_status(binary_id=binary_id)
    status = response.actual_instance

    await _fetch_and_apply_inferences()

    if isinstance(status, BinaryAnalysisIdle):
        # Server completed at least the revision stored in DB
        # before calling API.
        progress = revision
        result = "stop"
    elif isinstance(status, BinaryAnalysisInProgress):
        progress = status.revision - 1 + status.progress
        result = "continue_polling"
    else:
        raise Exception(f"Unknown status: {status}")

    await env.server_states.post(ServerStateChanged(revision_progress=progress))

    return result


async def _fetch_and_apply_inferences():
    env = Env.get()
    binary_id = await state.get_binary_id()
    cursor = await state.get_revision_cursor()
    current_revision = await state.get_current_revision()

    while True:
        if current_revision is None:
            break

        result = await env.binaries_api.get_inferences(
            binary_id=binary_id,
            revision_number=current_revision,
            cursor=cursor,
        )

        if len(result.inferences) > 0:
            await inferences.apply_inferences(result.inferences)

        cursor = result.cursor
        await state.set_revision_cursor(cursor)

        if not result.has_next:
            break
