import typing as ty
import typing_extensions as tye
from aiostream import stream

from decompai_ida import state, status
from decompai_ida.env import Env
from decompai_ida.poll_server_status import ServerStateChanged
from decompai_ida.upload_revisions import RevisionUploaded


async def monitor_analysis():
    env = Env.get()

    # Revision on which current progress started showing.
    base_revision = None
    # Revision on which current analysis is expected to end.
    target_revision = await state.get_current_revision()
    # Current server fractional revision (done plus progress on current).
    server_progress: ty.Optional[float] = None

    async with (
        status.begin_task("remote_work", start=False) as task,
        env.server_states.subscribe() as server_states,
        env.uploaded_revisions.subscribe() as uploaded_revisions,
        stream.merge(server_states, uploaded_revisions).stream() as updates,
    ):
        async for update in updates:
            if isinstance(update, RevisionUploaded):
                target_revision = update.revision
            elif isinstance(update, ServerStateChanged):
                server_progress = update.revision_progress
            else:
                _: tye.Never = update

            if server_progress is None:
                # Server status still unknown
                continue

            if server_progress >= target_revision:
                # Analysis done.
                base_revision = None
                await task.mark_done()
                continue

            if base_revision is None:
                # Analysis started.
                base_revision = int(server_progress)

            # Update progress
            await task.set_progress(
                (server_progress - base_revision)
                / (target_revision - base_revision)
            )
