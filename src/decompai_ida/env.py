import contextvars
import typing as ty
from contextlib import contextmanager
from dataclasses import dataclass

import anyio

# Avoid cyclic dependencies
if ty.TYPE_CHECKING:
    from decompai_client import BinariesApi
    from decompai_ida import ida_events
    from decompai_ida.broadcast import Broadcast
    from decompai_ida.poll_server import ServerStateChanged
    from decompai_ida.state import State
    from decompai_ida.status import StatusSummary, TaskUpdate
    from decompai_ida.upload_revisions import RevisionUploaded, UploadRevisions

_current_env = contextvars.ContextVar("current_env")


@dataclass(frozen=True, eq=False)
class Env:
    "Objects shared across all tasks"

    @staticmethod
    def get() -> "Env":
        """
        Get the currente environment (set by `use`).
        """
        return _current_env.get()

    @contextmanager
    def use(self):
        """
        Use given environment in context.
        """
        token = _current_env.set(self)
        try:
            yield
        finally:
            _current_env.reset(token)

    state: "State"
    binaries_api: "BinariesApi"
    events: "Broadcast[ida_events.Event]"
    revisions: "Broadcast[UploadRevisions]"
    uploaded_revisions: "Broadcast[RevisionUploaded]"
    task_updates: "Broadcast[TaskUpdate]"
    status_summaries: "Broadcast[ty.Optional[StatusSummary]]"
    server_states: "Broadcast[ServerStateChanged]"
    initial_analysis_complete: anyio.Event
