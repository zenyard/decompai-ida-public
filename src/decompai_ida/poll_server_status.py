import typing as ty
from dataclasses import dataclass

import anyio

from decompai_client import BinaryAnalysisIdle, BinaryAnalysisInProgress
from decompai_ida import api, logger, state, status
from decompai_ida.env import Env

_POLL_INTERVAL = 1


@dataclass(frozen=True)
class ServerStateChanged:
    # Server revision - done plus progress on current.
    revision_progress: float


@logger.instrument(task="poll_server_status")
async def poll_server_status_task():
    env = Env.get()

    async with env.uploaded_revisions.subscribe() as uploaded_revisions:
        while True:
            await _poll_server()

            # Restart after next upload
            await uploaded_revisions.receive()


async def _poll_server():
    await logger.get().ainfo("Starting to poll server status")
    async with status.begin_task("remote_work", start=False) as task:
        while True:
            try:
                result = await _poll_server_once()
                await task.mark_done()

                if result == "stop":
                    break

            except Exception as ex:
                is_temporary = api.is_temporary_error(ex)

                await logger.get().awarning(
                    "Error while polling server status",
                    exc_info=ex,
                    is_temporary=is_temporary,
                )

                if is_temporary:
                    await task.set_warning()
                else:
                    raise

            await anyio.sleep(_POLL_INTERVAL)
    await logger.get().ainfo("Done pollling server status")


async def _poll_server_once() -> ty.Literal["stop", "continue_polling"]:
    env = Env.get()
    binary_id = await state.get_binary_id()

    revision = await state.get_current_revision()
    response = await env.binaries_api.get_status(binary_id=binary_id)
    status = response.actual_instance

    log = logger.get().bind(local_revision=revision)

    if isinstance(status, BinaryAnalysisIdle):
        # Server completed at least the revision stored in DB
        # before calling API.
        progress = revision
        result = "stop"
        log = log.bind(server_status="idle")
    elif isinstance(status, BinaryAnalysisInProgress):
        progress = status.revision - 1 + status.progress
        result = "continue_polling"
        log = log.bind(
            server_status="in_progress",
            server_revision=status.revision,
            server_progress=status.progress,
        )
    else:
        raise Exception(f"Unknown status: {status}")

    await log.ainfo("Analysis progress update", progress=progress)

    await env.server_states.post(ServerStateChanged(revision_progress=progress))

    return result
