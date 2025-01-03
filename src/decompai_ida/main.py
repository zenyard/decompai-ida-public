from dataclasses import dataclass

import anyio
import exceptiongroup
import ida_auto
import ida_kernwin

from decompai_client import ApiClient, BinariesApi, PostBinaryBody
from decompai_client.exceptions import ForbiddenException, UnauthorizedException
from decompai_ida import api, binary, ida_events, ida_tasks, status
from decompai_ida.async_utils import wait_for_object_of_type
from decompai_ida.broadcast import Broadcast, RecordLatest
from decompai_ida.env import Env
from decompai_ida.initial_analysis import perform_initial_analysis
from decompai_ida.monitor_analysis import monitor_analysis
from decompai_ida.poll_server import poll_server_task
from decompai_ida.state import State
from decompai_ida.track_changes import track_changes_task
from decompai_ida.upload_revisions import upload_revisions_task

_MAX_SUPPORTED_BINARY_SIZE_MB = 2
_OBJECTS_PER_REVISION = 256
_BUFFER_CHANGES_PERIOD = 1


async def main(event_collector: ida_events.EventCollector):
    try:
        # Use task group to ensure all exceptions are grouped.
        async with anyio.create_task_group():
            # Start pumping events to broadcast.
            events = Broadcast[ida_events.Event](ida_events.EventRecorder())
            await event_collector.set_async_handler(events.post)

            # Create API client early to detect configuration issues.
            async with await api.get_api_client() as api_client:
                await _watch_for_database(
                    _GlobalEnv(
                        events=events,
                        api_client=api_client,
                    )
                )

    except exceptiongroup.ExceptionGroup as ex:
        config_path = await api.get_config_path()

        if ex.subgroup(api.BadConfigurationFile):
            await ida_tasks.run_ui(
                ida_kernwin.warning,
                f"Bad or missing DecompAI configuration at '{config_path}.'\n\n"
                "Correct the configuration and restart IDA to enable DecompAI.",
            )
        elif ex.subgroup((UnauthorizedException, ForbiddenException)):
            await ida_tasks.run_ui(
                ida_kernwin.warning,
                f"Bad DecompAI credentials at '{config_path}.'\n\n"
                "Correct the configuration and restart IDA to enable DecompAI.",
            )
        else:
            exceptiongroup.print_exception(ex)


@dataclass(frozen=True)
class _GlobalEnv:
    events: Broadcast[ida_events.Event]
    api_client: ApiClient


async def _watch_for_database(global_env: _GlobalEnv):
    """
    Watches when a database is opened or closed, spawns `_database_flow`.
    """
    async with global_env.events.subscribe() as event_receiver:
        while True:
            await wait_for_object_of_type(
                event_receiver, ida_events.DatabaseOpened
            )

            async with anyio.create_task_group() as tg:
                tg.start_soon(_database_flow, global_env)

                await wait_for_object_of_type(
                    event_receiver, ida_events.DatabaseClosed
                )

                tg.cancel_scope.cancel()


async def _database_flow(global_env: _GlobalEnv):
    if await binary.get_size() >= _MAX_SUPPORTED_BINARY_SIZE_MB * 2**20:
        await ida_tasks.run_ui(
            ida_kernwin.warning,
            "The demo version of DecompAI supports binaries up to "
            f"{_MAX_SUPPORTED_BINARY_SIZE_MB}MB (full versions have no limit). "
            "As this database exceeds the limit, DecompAI has been disabled for this session.",
        )
        return

    async with anyio.create_task_group() as tg:
        env = Env(
            state=await State.create(),
            binaries_api=BinariesApi(global_env.api_client),
            events=global_env.events,
            revisions=Broadcast(),
            uploaded_revisions=Broadcast(RecordLatest()),
            task_updates=Broadcast(),
            status_summaries=Broadcast(RecordLatest()),
            server_states=Broadcast(RecordLatest()),
            initial_analysis_complete=anyio.Event(),
        )

        with env.use():
            tg.start_soon(status.summarize_task_updates)
            tg.start_soon(status.report_status_summary_at_status_bar)

            is_unregistered = (await env.state.try_get_binary_id()) is None
            if is_unregistered:
                await _register_binary()
                tg.start_soon(_upload_original_files)

            tg.start_soon(monitor_analysis)
            tg.start_soon(upload_revisions_task)
            tg.start_soon(poll_server_task)
            tg.start_soon(track_changes_task, _BUFFER_CHANGES_PERIOD)

            await _wait_for_auto_analysis()
            tg.start_soon(perform_initial_analysis, _OBJECTS_PER_REVISION)


async def _register_binary():
    env = Env.get()

    existing_binary_id = await env.state.try_get_binary_id()
    assert existing_binary_id is None

    binary_path = await binary.get_binary_path()
    post_body = PostBinaryBody(name=binary_path.name)

    async with status.begin_task("registering") as task:
        result = await api.retry_forever(
            lambda: env.binaries_api.create_binary(post_body), task=task
        )

    await env.state.set_binary_id(result.binary_id)


async def _wait_for_auto_analysis():
    async with (
        Env.get().events.subscribe() as event_receiver,
        status.begin_task("waiting_for_ida"),
    ):
        while not await ida_tasks.run_read(ida_auto.auto_is_ok):
            with anyio.move_on_after(1):
                await wait_for_object_of_type(
                    event_receiver,
                    ida_events.InitialAutoAnalysisComplete,
                )


async def _upload_original_files():
    env = Env.get()
    binary_id = await env.state.get_binary_id()

    try:
        input_file = await binary.read_compressed_input_file()
    except Exception:
        # Not critical for plugin.
        return

    async with status.begin_task("local_work") as task:
        while True:
            try:
                await env.binaries_api.put_original_file(
                    binary_id=binary_id,
                    name=input_file.name,
                    data=input_file.data,
                )
                break

            except Exception as ex:
                if api.is_temporary_error(ex):
                    await task.set_warning()
                    continue

                else:
                    # Not critical for plugin.
                    break
