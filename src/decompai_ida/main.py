from contextlib import asynccontextmanager
from dataclasses import dataclass

import anyio
import exceptiongroup
import ida_kernwin

from decompai_client import BinariesApi, PostBinaryBody
from decompai_client.exceptions import ForbiddenException, UnauthorizedException
from decompai_ida import (
    api,
    binary,
    ida_events,
    ida_tasks,
    state,
    status,
    configuration,
)
from decompai_ida.async_utils import wait_for_object_of_type
from decompai_ida.broadcast import Broadcast, RecordLatest
from decompai_ida.env import Env
from decompai_ida.inferences import clear_inferences_marks_task
from decompai_ida.monitor_analysis import monitor_analysis
from decompai_ida.poll_server import poll_server_task
from decompai_ida.state import StateNodes
from decompai_ida.track_changes import track_changes_task
from decompai_ida.upload_revisions import (
    UploadRevisionsOptions,
    upload_revisions_task,
)

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

            # Read configuration early to detect issues.
            plugin_config = await configuration.read_configuration()

            await _watch_for_database(
                _GlobalEnv(
                    event_collector=event_collector,
                    events=events,
                    plugin_config=plugin_config,
                )
            )

    except exceptiongroup.ExceptionGroup as ex:
        config_path = await configuration.get_config_path()

        if ex.subgroup(configuration.BadConfigurationFile):
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
    event_collector: ida_events.EventCollector
    events: Broadcast[ida_events.Event]
    plugin_config: configuration.PluginConfiguration


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
    async with (
        hook_hexrays(global_env.event_collector),
        api.get_api_client(global_env.plugin_config) as api_client,
        anyio.create_task_group() as tg,
    ):
        env = Env(
            state_nodes=await ida_tasks.run(StateNodes),
            binaries_api=BinariesApi(api_client),
            events=global_env.events,
            uploaded_revisions=Broadcast(RecordLatest()),
            task_updates=Broadcast(),
            status_summaries=Broadcast(RecordLatest()),
            server_states=Broadcast(RecordLatest()),
            check_addresses=Broadcast(),
        )

        with env.use():
            should_work_on_db = await _should_work_on_db(
                global_env.plugin_config
            )

            tg.start_soon(status.summarize_task_updates)
            tg.start_soon(
                status.report_status_summary_at_status_bar,
                status.ReportStatusSummaryOptions(
                    is_plugin_enabled=should_work_on_db
                ),
            )

            if should_work_on_db:
                is_unregistered = (await state.try_get_binary_id()) is None
                if is_unregistered:
                    await _register_binary()
                    tg.start_soon(_upload_original_files)

                tg.start_soon(
                    upload_revisions_task,
                    UploadRevisionsOptions(
                        objects_per_revision=_OBJECTS_PER_REVISION,
                        buffer_changes_period=_BUFFER_CHANGES_PERIOD,
                    ),
                )
                tg.start_soon(clear_inferences_marks_task)
                tg.start_soon(monitor_analysis)
                tg.start_soon(poll_server_task)

                await anyio.sleep(0.1)  # Let previous tasks start
                tg.start_soon(track_changes_task)


async def _should_work_on_db(
    plugin_config: configuration.PluginConfiguration,
) -> bool:
    user_confirmation = await state.get_user_confirmation()

    if user_confirmation is None and plugin_config.require_confirmation_per_db:
        result = await ida_tasks.run_ui(
            ida_kernwin.ask_buttons,
            "Yes",
            "Skip",
            "Cancel",
            ida_kernwin.ASKBTN_NO,
            "HIDECANCEL\nWould you like DecompAI to run on this file?",
        )
        user_confirmation = result == ida_kernwin.ASKBTN_YES

        await state.set_user_confirmation(user_confirmation)

    # Note that user_confirmation can still be `None` for undecided here.
    if user_confirmation == False:  # noqa: E712
        return False

    if await binary.get_size() >= _MAX_SUPPORTED_BINARY_SIZE_MB * 2**20:
        await ida_tasks.run_ui(
            ida_kernwin.warning,
            "The demo version of DecompAI supports binaries up to "
            f"{_MAX_SUPPORTED_BINARY_SIZE_MB}MB (full versions have no limit). "
            "As this database exceeds the limit, DecompAI has been disabled for this session.",
        )
        return False

    return True


@asynccontextmanager
async def hook_hexrays(event_collector: ida_events.EventCollector):
    """
    Hook HexRays. Note that doing this in plugin entry causes crashes.
    """
    hexrays_hooks = ida_events.HexRaysHooks(event_collector)
    await ida_tasks.run_ui(hexrays_hooks.hook)
    try:
        yield
    finally:
        await ida_tasks.run_ui(hexrays_hooks.unhook)


async def _register_binary():
    env = Env.get()

    existing_binary_id = await state.try_get_binary_id()
    assert existing_binary_id is None

    binary_path = await binary.get_binary_path()
    post_body = PostBinaryBody(name=binary_path.name)

    async with status.begin_task("registering") as task:
        result = await api.retry_forever(
            lambda: env.binaries_api.create_binary(post_body), task=task
        )

    await state.set_binary_id(result.binary_id)


async def _upload_original_files():
    env = Env.get()
    binary_id = await state.get_binary_id()

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
