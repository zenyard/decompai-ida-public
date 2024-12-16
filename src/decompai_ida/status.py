"""
Utilities for reporting progress of background tasks.

Example of reporting progress in task:

    ```python
    with status.begin_task("my task") as task_progress:
        task_progress.set_item_count(10)  # optional
        task_progress.mark_item_complete()  # optional
    ```
"""

from contextlib import asynccontextmanager
import typing as ty
from collections import OrderedDict
from dataclasses import dataclass

import anyio

from decompai_ida import ida_events
from decompai_ida.async_utils import wait_for_object_of_type
from decompai_ida.broadcast import Broadcast, RecordLatest
from decompai_ida.env import Env


@dataclass(frozen=True, kw_only=True)
class TaskUpdate:
    Progress: ty.TypeAlias = int | ty.Literal["started"] | ty.Literal["done"]
    """
    Task progress:
     - "started" - in progress, but progress can't be determined yet.
     - int between 0 and 100 - progress percentage.
     - "done" - complete.
    """

    id: int
    task_name: str
    progress: Progress
    priority: int
    warning: str | None


class Task:
    @dataclass(frozen=True)
    class _Started:
        def to_progress(self) -> TaskUpdate.Progress:
            return "started"

    @dataclass(frozen=True)
    class _Done:
        def to_progress(self) -> TaskUpdate.Progress:
            return "done"

    @dataclass(frozen=True, kw_only=True)
    class _Items:
        completed: int = 0
        total: int

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
            return Task._Items(completed=self.completed + 1, total=self.total)

    @dataclass(frozen=True)
    class _Percentage:
        value: float

        def to_progress(self) -> TaskUpdate.Progress:
            return int(self.value * 100)

    _State: ty.TypeAlias = _Started | _Done | _Items | _Percentage

    def __init__(
        self,
        name: str,
        priority: int,
    ):
        self._name = name
        self._task_updates = Env.get().task_updates
        self._priority = priority
        self._state: Task._State = Task._Started()
        self._warning: str | None = None
        self._last_update: TaskUpdate | None = None

    async def set_item_count(self, n: int):
        self._state = Task._Items(completed=0, total=n)
        await self._send_update()

    async def mark_item_complete(self):
        """
        Reports one item completed.
        """
        assert isinstance(self._state, Task._Items)
        self._warning = None
        self._state = self._state.with_completed_item()
        await self._send_update()

    async def mark_done(self):
        self._warning = None
        self._state = Task._Done()
        await self._send_update()

    async def set_progress(self, value: float):
        self._warning = None
        self._state = Task._Percentage(value)
        await self._send_update()

    async def set_warning(self, warning: str):
        if isinstance(self._state, Task._Done):
            self._state = Task._Started()
        self._warning = warning
        await self._send_update()

    async def clear_warning(self):
        self._warning = None
        await self._send_update()

    async def _send_update(self):
        update = TaskUpdate(
            id=id(self),
            task_name=self._name,
            progress=self._state.to_progress(),
            priority=self._priority,
            warning=self._warning,
        )

        if update != self._last_update:
            await self._task_updates.post(update)
            self._last_update = update


@asynccontextmanager
async def begin_task(
    name: str,
    *,
    priority: int = 0,
    start: bool = True,
    item_count: int | None = None,
) -> ty.AsyncGenerator["Task", None]:
    """
    Start a new task. Task is marked as done when context exits.
    """
    task = Task(name, priority=priority)
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


async def report_status_task():
    """
    Show task status in UI.
    """

    overall_status = Broadcast[_OverallStatus](RecordLatest())
    async with anyio.create_task_group() as tg:
        tg.start_soon(
            _print_task_updates_and_broadcast_overall_status,
            overall_status,
        )
        tg.start_soon(
            _report_overall_status_at_status_bar,
            overall_status,
        )


async def _print_task_updates_and_broadcast_overall_status(
    overall_status_broadcast: Broadcast["_OverallStatus"],
):
    tasks = OrderedDict[int, TaskUpdate]()
    last_overall_status: _OverallStatus | None = None

    async with Env.get().task_updates.subscribe() as task_updates:
        async for update in task_updates:
            if update.progress == "done":
                tasks.pop(update.id, None)
            else:
                tasks[update.id] = update

            overall_status = _OverallStatus.from_task_updates(tasks.values())

            if overall_status != last_overall_status:
                await overall_status_broadcast.post(overall_status)
                last_overall_status = overall_status


async def _report_overall_status_at_status_bar(
    overall_status_broadcast: Broadcast["_OverallStatus"],
):
    # This requires PyQt5.
    try:
        from decompai_ida.status_bar_widget import status_bar_widget_updater
    except ImportError:
        return

    # Wait for main window.
    async with Env.get().events.subscribe() as events_receiver:
        await wait_for_object_of_type(events_receiver, ida_events.MainUiReady)

    # Pump overall status updates to status bar.
    async with (
        overall_status_broadcast.subscribe() as overall_status_receiver,
        status_bar_widget_updater() as update_status_bar,
    ):
        async for overall_status in overall_status_receiver:
            # In case of idle, wait a bit to allow for another task to begin
            # before updating UI, to avoid quick updates in this common case.
            if isinstance(overall_status.status, _OverallStatus.Ready):
                with anyio.move_on_after(0.25):
                    overall_status = await overall_status_receiver.receive()

            match overall_status.status:
                case _OverallStatus.Ready():
                    text = "Ready"
                    progress = None
                case _OverallStatus.Busy(text):
                    progress = "busy"
                case _OverallStatus.InProgress(text, progress):
                    pass

            await update_status_bar(
                text=text, progress=progress, warning=overall_status.warning
            )


def _format_report(updates: ty.Sequence[TaskUpdate]):
    if len(updates) > 0:
        return ", ".join(
            f"{task.task_name} ({task.progress}%)"
            if isinstance(task.progress, int)
            else task.task_name
            for task in updates
        )
    else:
        return "idle"


@dataclass(frozen=True, kw_only=True)
class _OverallStatus:
    @dataclass(frozen=True)
    class Ready:
        pass

    @dataclass(frozen=True)
    class Busy:
        text: str

    @dataclass(frozen=True)
    class InProgress:
        text: str
        progress: int

    status: Ready | Busy | InProgress
    warning: str | None = None

    @staticmethod
    def from_task_updates(
        updates: ty.Iterable[TaskUpdate],
    ) -> "_OverallStatus":
        updates = list(updates)

        if len(updates) == 0:
            return _OverallStatus(status=_OverallStatus.Ready())

        by_priority = sorted(
            updates, key=lambda update: update.priority, reverse=True
        )

        highest_priority = by_priority[0]
        match highest_priority.progress:
            case "started" | "done":
                status = _OverallStatus.Busy(highest_priority.task_name)
            case int(progress):
                status = _OverallStatus.InProgress(
                    highest_priority.task_name, progress
                )

        warning = next(
            (
                update.warning
                for update in by_priority
                if update.warning is not None
            ),
            None,
        )

        return _OverallStatus(status=status, warning=warning)
