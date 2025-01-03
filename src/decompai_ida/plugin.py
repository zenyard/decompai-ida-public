from threading import Thread

import anyio
import ida_idaapi

from decompai_ida import ida_events
from decompai_ida.main import main


class StopSignal:
    stopped = False


class DecompaiPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX  # type: ignore
    wanted_name = "Decompai"

    def init(self):
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
        return ida_idaapi.PLUGIN_KEEP  # type: ignore

    def term(self):  # type: ignore
        self._ui_hooks.unhook()
        self._db_hooks.unhook()
        self._stop_signal.stopped = True
        self._thread.join()


def main_loop(
    stop_signal: StopSignal, event_collector: ida_events.EventCollector
):
    async def main_with_stop_signal():
        async with anyio.create_task_group() as tg:
            tg.start_soon(main, event_collector)
            # Waiting on `Event` doesn't work, as it can't be signalled from
            # outside the loop.
            while not stop_signal.stopped:
                await anyio.sleep(1)
            tg.cancel_scope.cancel()

    anyio.run(main_with_stop_signal)


def PLUGIN_ENTRY():
    return DecompaiPlugin()
