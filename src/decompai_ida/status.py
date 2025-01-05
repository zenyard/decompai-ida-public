"""
Utilities for reporting progress of background tasks.

Example of reporting progress in task:

    ```python
    with status.begin_task("local_work", item_count=10) as task_progress:
        task_progress.mark_item_complete()  # optional
    ```
"""

import time
import typing as ty
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass

import anyio
import typing_extensions as tye

from decompai_ida import ida_events
from decompai_ida.async_utils import wait_for_object_of_type
from decompai_ida.env import Env

TaskKind: tye.TypeAlias = ty.Literal[
    # Registering binary at server.
    "registering",
    # E.g. waiting for auto-analysis.
    "waiting_for_ida",
    # Tasks that require IDA to remain open. E.g. decompiling, uploading.
    "local_work",
    # Tasks that don't require IDA to remain open. E.g. analysis on server,
    # downloading.
    "remote_work",
]
"Determines how the task is shown to user"

# Determines which task is preferred in status summary.
_TASK_KIND_PRIORITY: ty.Mapping[TaskKind, int] = {
    # Only interesting in case no other task is active, to let user know
    # we're waiting.
    "waiting_for_ida": 0,
    "remote_work": 1,
    # Most interesting - user must keep IDA open for the duration of this
    # task.
    "local_work": 2,
    "registering": 2,
}

# Text to show in UI for each kind of task.
_TASK_KIND_LABEL: ty.Mapping[TaskKind, str] = {
    "waiting_for_ida": "Waiting for IDA",
    "local_work": "Preparing data locally",
    "remote_work": "Reversing on server",
    "registering": "Registering at server",
}

# Text to show when no task is active.
_IDLE_LABEL = "Ready"

# Text to show on warning tooltip
_WARNING_LABEL = "Can't reach server"

# Time, in seconds, between warning being set until it is actually reported to
# user.
_WARNING_GRACE_PERIOD = 60


@dataclass(frozen=True)
class TaskUpdate:
    id: int
    task_kind: TaskKind
    progress: "Progress"
    warning: bool = False

    Progress: tye.TypeAlias = ty.Union[
        int, ty.Literal["started"], ty.Literal["done"]
    ]
    """
    Task progress:
     - "started" - in progress, but progress can't be determined yet.
     - int between 0 and 100 - progress percentage.
     - "done" - complete.
    """


class Task:
    @dataclass(frozen=True)
    class _Started:
        def to_progress(self) -> TaskUpdate.Progress:
            return "started"

    @dataclass(frozen=True)
    class _Done:
        def to_progress(self) -> TaskUpdate.Progress:
            return "done"

    @dataclass(frozen=True)
    class _Items:
        total: int
        completed: int = 0

        def to_progress(self) -> TaskUpdate.Progress:
            percentage = int((self.completed / self.total) * 100)
            if percentage == 0 and self.total == 1:
                # Don't show progress bar for one item
                return "started"
            elif percentage == 100:
                return "done"
            else:
                return percentage

        def with_completed_item(self) -> "Task._Items":
            return Task._Items(total=self.total, completed=self.completed + 1)

    @dataclass(frozen=True)
    class _Percentage:
        value: float

        def to_progress(self) -> TaskUpdate.Progress:
            return int(self.value * 100)

    _State: tye.TypeAlias = ty.Union[_Started, _Done, _Items, _Percentage]

    def __init__(
        self,
        kind: TaskKind,
    ):
        self._kind: TaskKind = kind
        self._task_updates = Env.get().task_updates
        self._state: Task._State = Task._Started()
        self._warning_start_time: ty.Optional[float] = None
        self._last_update: ty.Optional[TaskUpdate] = None

    async def set_item_count(self, n: int):
        self._state = Task._Items(total=n, completed=0)
        await self._send_update()

    async def mark_item_complete(self):
        """
        Reports one item completed.
        """
        assert isinstance(self._state, Task._Items)
        self._warning_start_time = None
        self._state = self._state.with_completed_item()
        await self._send_update()

    async def mark_done(self):
        self._warning_start_time = None
        self._state = Task._Done()
        await self._send_update()

    async def set_progress(self, value: float):
        self._warning_start_time = None
        self._state = Task._Percentage(value)
        await self._send_update()

    async def set_warning(self):
        if isinstance(self._state, Task._Done):
            self._state = Task._Started()
        if self._warning_start_time is None:
            self._warning_start_time = _get_monotonic_time()
        await self._send_update()

    async def clear_warning(self):
        self._warning_start_time = None
        await self._send_update()

    async def _send_update(self):
        warning = self._warning_start_time is not None and (
            _get_monotonic_time() - self._warning_start_time
            > _WARNING_GRACE_PERIOD
        )

        update = TaskUpdate(
            id=id(self),
            task_kind=self._kind,
            progress=self._state.to_progress(),
            warning=warning,
        )

        if update != self._last_update:
            await self._task_updates.post(update)
            self._last_update = update


@asynccontextmanager
async def begin_task(
    kind: TaskKind,
    *,
    priority: int = 0,
    start: bool = True,
    item_count: ty.Optional[int] = None,
) -> ty.AsyncGenerator["Task", None]:
    """
    Start a new task. Task is marked as done when context exits.
    """
    task = Task(kind)
    if start:
        if item_count is not None:
            await task.set_item_count(item_count)
        else:
            await task._send_update()
    try:
        yield task
    finally:
        with anyio.CancelScope(shield=True):
            await task.mark_done()


async def summarize_task_updates():
    """
    Aggregate task updates and send `StatusSummary` objects.
    """

    env = Env.get()
    tasks = OrderedDict[int, TaskUpdate]()
    last_status_summary: ty.Optional[StatusSummary] = None

    async with env.task_updates.subscribe() as task_updates:
        async for update in task_updates:
            if update.progress == "done":
                tasks.pop(update.id, None)
            else:
                tasks[update.id] = update

            status_summary = StatusSummary.from_task_updates(tasks.values())

            if status_summary != last_status_summary:
                await env.status_summaries.post(status_summary)
                last_status_summary = status_summary


async def report_status_summary_at_status_bar():
    # This requires PyQt5.
    try:
        from decompai_ida.status_bar_widget import status_bar_widget_updater
    except ImportError:
        return

    env = Env.get()

    # Wait for main window.
    async with Env.get().events.subscribe() as events_receiver:
        await wait_for_object_of_type(events_receiver, ida_events.MainUiReady)

    # Pump status summaries to status bar widget.
    async with (
        env.status_summaries.subscribe() as status_summary_receiver,
        status_bar_widget_updater() as update_status_bar,
    ):
        async for status_summary in status_summary_receiver:
            # In case of idle, wait a bit to allow for another task to begin
            # before updating UI, to avoid quick updates in this common case.
            if status_summary is None:
                with anyio.move_on_after(0.25):
                    status_summary = await status_summary_receiver.receive()

            if status_summary is not None:
                text = _TASK_KIND_LABEL[status_summary.task_kind]
                progress = status_summary.progress
                warning = _WARNING_LABEL if status_summary.warning else None
            else:
                text = _IDLE_LABEL
                progress = None
                warning = None

            await update_status_bar(
                text=text, progress=progress, warning=warning
            )


@dataclass(frozen=True)
class StatusSummary:
    """
    Summary of active tasks.
    """

    task_kind: TaskKind
    progress: ty.Union[int, ty.Literal["started"]]
    warning: bool = False

    @staticmethod
    def from_task_updates(
        updates: ty.Iterable[TaskUpdate],
    ) -> ty.Optional["StatusSummary"]:
        updates = list(updates)

        if len(updates) == 0:
            return None

        def priority_for_task_update(update: TaskUpdate) -> tuple[int, bool]:
            # Sort first by kind, then prefer showing actual progress
            kind_priority = _TASK_KIND_PRIORITY[update.task_kind]
            has_progress = isinstance(update.progress, int)
            return kind_priority, has_progress

        by_priority = sorted(
            updates, key=priority_for_task_update, reverse=True
        )
        highest_priority = by_priority[0]
        assert highest_priority.progress != "done"

        any_warning = any(update.warning for update in by_priority)

        return StatusSummary(
            task_kind=highest_priority.task_kind,
            progress=highest_priority.progress,
            warning=any_warning,
        )


# Patched in tests
_get_monotonic_time = time.monotonic
