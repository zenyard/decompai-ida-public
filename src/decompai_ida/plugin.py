import typing as ty
from threading import Thread

import anyio
import ida_idaapi

from decompai_ida import configuration, ida_events, ida_tasks
from decompai_ida.main import main


class StopSignal:
    callback: ty.Optional[ida_tasks.AsyncCallback[[]]] = None


class DecompaiPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_MULTI  # type: ignore
    wanted_name = "DecompAI"

    def init(self):
        return DecompaiPlugmod()


class DecompaiPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        # Install hooks immediately, so we don't miss any event.
        self._event_collector = ida_events.EventCollector()
        self._ui_hooks = ida_events.UiEventHooks(self._event_collector)
        self._ui_hooks.hook()
        self._db_hooks = ida_events.DbEventHooks(self._event_collector)
        self._db_hooks.hook()

        self._stop_signal = StopSignal()
        self._thread = Thread(
            target=main_loop, args=(self._stop_signal, self._event_collector)
        )
        self._thread.start()

    def run(self, _arg):  # type: ignore
        configuration.show_configuration_dialog.sync()

    def __del__(self):
        self._ui_hooks.unhook()
        self._db_hooks.unhook()
        if self._stop_signal.callback is not None:
            self._stop_signal.callback()
        self._thread.join()


def main_loop(
    stop_signal: StopSignal, event_collector: ida_events.EventCollector
):
    async def main_with_stop_signal():
        # Note that events cannot be signalled from outside the loop. That's why
        # we create an `AsyncCallback` from within the loop and put it in a
        # shared place.
        stop_event = anyio.Event()
        stop_signal.callback = ida_tasks.AsyncCallback(stop_event.set)

        async with anyio.create_task_group() as tg:
            tg.start_soon(main, event_collector)
            await stop_event.wait()
            tg.cancel_scope.cancel()

    anyio.run(main_with_stop_signal)


def PLUGIN_ENTRY():
    return DecompaiPlugin()
