"""
Types for collecting IDA events.

Events generated from our own code are never collected.
"""

import threading
import typing as ty
from dataclasses import dataclass

import ida_idp
import ida_kernwin
import typing_extensions as tye

from decompai_ida import ida_tasks
from decompai_ida.broadcast import Recorder, RecordLatestOfEachType


@dataclass(frozen=True)
class DatabaseOpened:
    pass


@dataclass(frozen=True)
class DatabaseClosed:
    pass


@dataclass(frozen=True)
class MainUiReady:
    pass


@dataclass(frozen=True)
class AddressRenamed:
    address: int
    old_name: str
    new_name: str
    is_local: bool


@dataclass(frozen=True)
class InitialAutoAnalysisComplete:
    pass


Event: tye.TypeAlias = ty.Union[
    DatabaseOpened,
    DatabaseClosed,
    MainUiReady,
    AddressRenamed,
    InitialAutoAnalysisComplete,
]


class EventCollector:
    """
    Allows collecting events from IDA's callbacks, and handling them from async
    context.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._target: ty.Union[
            list[Event], ida_tasks.AsyncCallback[[Event]]
        ] = []

    def add(self, event: Event):
        with self._lock:
            if isinstance(self._target, list):
                self._target.append(event)
                return
            else:
                callback = self._target

        # Filter events generated from our own tasks.
        if not ida_tasks.is_running_in_task():
            callback(event)

    async def set_async_handler(
        self, handler: ty.Callable[[Event], ty.Awaitable[None]]
    ):
        """
        Set event handler. This will immediately handle all collected events.

        Handler must not raise.
        """

        # Keep pumping events out until empty, only then switch target to
        # callback. This prevents newer events from being handled before
        # buffered events.
        while True:
            with self._lock:
                if not isinstance(self._target, list) or len(self._target) == 0:
                    self._target = ida_tasks.AsyncCallback(handler)
                    return

                events = self._target
                self._target = []

            for event in events:
                await handler(event)


class UiEventHooks(ida_kernwin.UI_Hooks):
    def __init__(self, collector: EventCollector):
        super().__init__()
        self._collector = collector

    def database_inited(self, is_new_database: "int", idc_script: str, /):
        self._collector.add(DatabaseOpened())

    def database_closed(self, /):
        self._collector.add(DatabaseClosed())

    def ready_to_run(self, /):
        self._collector.add(MainUiReady())


class DbEventHooks(ida_idp.IDB_Hooks):
    def __init__(self, collector: EventCollector):
        super().__init__()
        self._collector = collector

    def auto_empty_finally(self, /):
        self._collector.add(InitialAutoAnalysisComplete())

    def renamed(
        self, ea: int, new_name: str, local_name: bool, old_name: str, /
    ):
        self._collector.add(
            AddressRenamed(
                address=ea,
                old_name=old_name,
                new_name=new_name,
                is_local=local_name,
            )
        )


class EventRecorder(Recorder):
    """
    Records last event of each type, but drops all events when DB closes.
    """

    def __init__(self) -> None:
        self._inner = RecordLatestOfEachType[Event]()

    def record(self, message: Event):
        if isinstance(message, DatabaseClosed):
            self._inner.clear()
        else:
            self._inner.record(message)

    def get_recorded(self) -> ty.Iterable[Event]:
        return self._inner.get_recorded()
