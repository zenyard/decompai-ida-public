"""
Types for collecting IDA events.

Events generated from our own code are never collected.
"""

import threading
import typing as ty
from dataclasses import dataclass

import ida_hexrays
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
class AddressModified:
    """
    Address was modified in some way (comment, name, type, etc.)

    This doesn't cover removal events (e.g. function removal).
    """

    address: int


@dataclass(frozen=True)
class InitialAutoAnalysisComplete:
    pass


Event: tye.TypeAlias = ty.Union[
    DatabaseOpened,
    DatabaseClosed,
    MainUiReady,
    AddressModified,
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


class _BaseHooks:
    def __init__(self, collector: EventCollector):
        super().__init__()
        self._collector = collector

    def _report_address_modified(self, address: int):
        assert isinstance(address, int), f"Got: {address}"
        self._collector.add(AddressModified(address=address))


class UiEventHooks(_BaseHooks, ida_kernwin.UI_Hooks):
    def database_inited(self, is_new_database, idc_script, /):
        self._collector.add(DatabaseOpened())
        return super().database_inited(is_new_database, idc_script)

    def database_closed(self, /):
        self._collector.add(DatabaseClosed())
        return super().database_closed()

    def ready_to_run(self, /):
        self._collector.add(MainUiReady())
        return super().ready_to_run()


class DbEventHooks(_BaseHooks, ida_idp.IDB_Hooks):
    def auto_empty_finally(self, /):
        self._collector.add(InitialAutoAnalysisComplete())
        return super().auto_empty_finally()

    # Note - func_update not handled, it creates a lot of false-positive
    # updates, while other events cover the cases we care about.

    # TODO
    # def func_deleted(self, func_ea, /):
    # def local_types_changed(self, ltc, ordinal, name, /):

    def func_added(self, pfn, /):
        self._report_address_modified(pfn.start_ea)
        return super().func_added(pfn)

    def func_tail_appended(self, pfn, tail, /):
        self._report_address_modified(pfn.start_ea)
        return super().func_tail_appended(pfn, tail)

    def func_tail_deleted(self, pfn, tail_ea, /):
        self._report_address_modified(pfn.start_ea)
        return super().func_tail_deleted(pfn, tail_ea)

    def tail_owner_changed(self, tail, owner_func, old_owner, /):
        self._report_address_modified(owner_func)
        self._report_address_modified(old_owner)
        return super().tail_owner_changed(tail, owner_func, old_owner)

    def func_noret_changed(self, pfn, /):
        self._report_address_modified(pfn.start_ea)
        return super().func_noret_changed(pfn)

    def thunk_func_created(self, pfn, /):
        self._report_address_modified(pfn.start_ea)
        return super().thunk_func_created(pfn)

    def callee_addr_changed(self, ea, callee, /):
        self._report_address_modified(ea)
        return super().callee_addr_changed(ea, callee)

    def ti_changed(self, ea, type, fnames, /):
        self._report_address_modified(ea)
        return super().ti_changed(ea, type, fnames)

    def op_ti_changed(self, ea, n, type, fnames, /):
        self._report_address_modified(ea)
        return super().op_ti_changed(ea, n, type, fnames)

    def op_type_changed(self, ea, n, /):
        self._report_address_modified(ea)
        return super().op_type_changed(ea, n)

    def renamed(self, ea, new_name, local_name, old_name, /):
        self._report_address_modified(ea)
        return super().renamed(ea, new_name, local_name, old_name)

    def cmt_changed(self, ea, repeatable_cmt, /):
        self._report_address_modified(ea)
        return super().cmt_changed(ea, repeatable_cmt)

    def extra_cmt_changed(self, ea, line_idx, cmt, /):
        self._report_address_modified(ea)
        return super().extra_cmt_changed(ea, line_idx, cmt)

    def range_cmt_changed(self, kind, a, cmt, repeatable, /):
        self._report_address_modified(a.start_ea)
        return super().range_cmt_changed(kind, a, cmt, repeatable)


class HexRaysHooks(_BaseHooks, ida_hexrays.Hexrays_Hooks):
    def cmt_changed(self, cfunc, loc, cmt, /) -> "int":
        self._report_address_modified(cfunc.entry_ea)
        return super().cmt_changed(cfunc, loc, cmt)

    def lvar_cmt_changed(self, vu, v, cmt, /) -> "int":
        self._report_address_modified(v.defea)
        return super().lvar_cmt_changed(vu, v, cmt)

    def lvar_mapping_changed(self, vu, frm, to, /) -> "int":
        self._report_address_modified(frm.defea)
        self._report_address_modified(to.defea)
        return super().lvar_mapping_changed(vu, frm, to)

    def lvar_name_changed(self, vu, v, name, is_user_name, /) -> "int":
        self._report_address_modified(v.defea)
        return super().lvar_name_changed(vu, v, name, is_user_name)

    def lvar_type_changed(self, vu, v, tinfo, /) -> "int":
        self._report_address_modified(v.defea)
        return super().lvar_type_changed(vu, v, tinfo)


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
