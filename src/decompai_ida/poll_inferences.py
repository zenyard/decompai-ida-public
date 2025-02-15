import typing as ty
import typing_extensions as tye
from dataclasses import dataclass

from aiostream import stream
import anyio

from decompai_client import Inference
from decompai_ida import api, inferences, state, status, logger
from decompai_ida.env import Env
from decompai_ida.poll_server_status import ServerStateChanged
from decompai_ida.upload_revisions import RevisionUploaded


_POLL_INTERVAL = 1
_MAX_INFERENCES_IN_ONE_REQUEST = 50


async def poll_inferences_task():
    async with anyio.create_task_group() as tg:
        analysis_status = _AnalysisStatus()
        tg.start_soon(_update_analysis_status_task, analysis_status)
        tg.start_soon(_poll_inferences_while_analyzing_task, analysis_status)


@dataclass
class _AnalysisStatus:
    done_revision: ty.Optional[int] = None


@logger.instrument(task="poll_inferences", subtask="update_analysis_status")
async def _update_analysis_status_task(analysis_status: _AnalysisStatus):
    env = Env.get()

    target_revision = await state.get_current_revision()
    server_progress: ty.Optional[float] = None

    async with (
        env.uploaded_revisions.subscribe() as uploaded_revisions,
        env.server_states.subscribe() as server_states,
        stream.merge(server_states, uploaded_revisions).stream() as updates,
    ):
        async for update in updates:
            if isinstance(update, RevisionUploaded):
                target_revision = update.revision
            elif isinstance(update, ServerStateChanged):
                server_progress = update.revision_progress
            else:
                _: tye.Never = update

            done_revision = (
                target_revision if server_progress == target_revision else None
            )
            await logger.get().adebug(
                "Update done revision", done_revision=done_revision
            )
            analysis_status.done_revision = done_revision


@logger.instrument(task="poll_inferences", subtask="poll_while_analyzing")
async def _poll_inferences_while_analyzing_task(
    analysis_status: _AnalysisStatus,
):
    last_done_revision = None

    while True:
        async with status.begin_task("applying_results", start=False) as task:
            if (
                last_done_revision is None
                or analysis_status.done_revision is None
                or last_done_revision < analysis_status.done_revision
            ):
                await task.set_started()
                last_done_revision = analysis_status.done_revision
                await _fetch_and_apply_inferences(task=task)
            else:
                await task.mark_done()

        await anyio.sleep(_POLL_INTERVAL)


async def _fetch_and_apply_inferences(*, task: status.Task):
    env = Env.get()
    binary_id = await state.get_binary_id()
    cursor = await state.get_revision_cursor()
    current_revision = await state.get_current_revision()

    while True:
        try:
            result = await env.binaries_api.get_inferences(
                binary_id=binary_id,
                revision_number=current_revision,
                cursor=cursor,
                limit=_MAX_INFERENCES_IN_ONE_REQUEST,
            )
            await task.clear_warning()

            known_inferences = [
                inference.actual_instance
                for inference in result.inferences
                if isinstance(inference.actual_instance, Inference)
            ]

            await logger.get().adebug(
                "Got inferences", count=len(known_inferences)
            )

            if len(known_inferences) > 0:
                await inferences.apply_inferences(known_inferences)

            cursor = result.cursor
            await state.set_revision_cursor(cursor)

            if not result.has_next:
                break

        except Exception as ex:
            if api.is_temporary_error(ex):
                await logger.get().awarning(
                    "Error while fetching inferences",
                    exc_info=True,
                    is_temporary=True,
                )
                await task.set_warning()
                await anyio.sleep(_POLL_INTERVAL)
            else:
                raise
