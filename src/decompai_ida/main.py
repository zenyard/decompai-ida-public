from dataclasses import dataclass
import anyio
import exceptiongroup
import ida_auto
import ida_kernwin

from decompai_client import ApiClient, BinariesApi
from decompai_client.exceptions import ForbiddenException, UnauthorizedException
from decompai_ida import api, ida_events, ida_tasks, status
from decompai_ida.async_utils import wait_for_object_of_type
from decompai_ida.broadcast import Broadcast
from decompai_ida.env import Env, use_env
from decompai_ida.initial_analysis import perform_initial_analysis
from decompai_ida.monitor_analysis import monitor_analysis
from decompai_ida.state import State
from decompai_ida.track_changes import track_changes_task
from decompai_ida.upload_revisions import upload_revisions_task


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
    async with anyio.create_task_group() as tg:
        env = Env(
            state=await State.create(),
            binaries_api=BinariesApi(global_env.api_client),
            events=global_env.events,
            revisions=Broadcast(),
            uploaded_revisions=Broadcast(),
            task_updates=Broadcast(),
        )

        with use_env(env):
            tg.start_soon(status.report_status_task)

            await _register_binary()

            tg.start_soon(monitor_analysis)
            tg.start_soon(upload_revisions_task)

            await _wait_for_auto_analysis()
            await perform_initial_analysis(objects_per_revision=256)
            await track_changes_task()


async def _register_binary():
    env = Env.get()

    existing_binary_id = await env.state.try_get_binary_id()
    if existing_binary_id is not None:
        return existing_binary_id

    async with status.begin_task("Registering database") as task:
        result = await api.retry_forever(
            env.binaries_api.create_binary, task=task
        )

    await env.state.set_binary_id(result.binary_id)


async def _wait_for_auto_analysis():
    async with (
        Env.get().events.subscribe() as event_receiver,
        status.begin_task("Waiting for AU"),
    ):
        while not await ida_tasks.run_read(ida_auto.auto_is_ok):
            with anyio.move_on_after(1):
                await wait_for_object_of_type(
                    event_receiver,
                    ida_events.InitialAutoAnalysisComplete,
                )
