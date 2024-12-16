import contextvars
import typing as ty
from contextlib import contextmanager
from dataclasses import dataclass

# Avoid cyclic dependencies
if ty.TYPE_CHECKING:
    from decompai_client import BinariesApi
    from decompai_ida import ida_events
    from decompai_ida.broadcast import Broadcast
    from decompai_ida.state import State
    from decompai_ida.status import TaskUpdate
    from decompai_ida.upload_revisions import UploadRevisions, RevisionUploaded

_current_env = contextvars.ContextVar("current_env")


@dataclass(frozen=True, kw_only=True, eq=False)
class Env:
    "Objects shared across all tasks"

    @staticmethod
    def get() -> "Env":
        return _current_env.get()

    state: "State"
    binaries_api: "BinariesApi"
    events: "Broadcast[ida_events.Event]"
    revisions: "Broadcast[UploadRevisions]"
    uploaded_revisions: "Broadcast[RevisionUploaded]"
    task_updates: "Broadcast[TaskUpdate]"


@contextmanager
def use_env(env: Env):
    """
    Use given environment in context.
    """
    token = _current_env.set(env)
    try:
        yield
    finally:
        _current_env.reset(token)
