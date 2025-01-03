"""
Allows running code that accesses IDA's API.

All utilities have 3 permission levels:
- ui - may only access UI.
- read - may also read from database.
- write - may also write to database.

Utilities:
- `ui/read/write` - decorator for converting sync code to async.
- `ui/read/write_generator` - decorator for converting sync generator to async generator.
- `run_ui/read/write` - call a sync function from async.
- `ui/read/write_iter` - turn iterator to async iterator (useful with idautils).
"""

import asyncio
import contextvars
import time
import typing as ty
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from itertools import islice

import anyio
import ida_kernwin
import typing_extensions as tye

_R = ty.TypeVar("_R", contravariant=True)
_P = tye.ParamSpec("_P")

_running_in_task = contextvars.ContextVar("running_in_task", default=False)


def is_running_in_task() -> bool:
    "Whether calling code runs on task invoked by this module"
    return _running_in_task.get()


@contextmanager
def _set_running_in_task(value: bool):
    token = _running_in_task.set(value)
    try:
        yield
    finally:
        _running_in_task.reset(token)


def _make_decorator(flags: int):
    def decorator(
        func: ty.Callable[_P, _R],
    ) -> ty.Callable[_P, ty.Awaitable[_R]]:
        @wraps(func)
        async def wrapped(*args: _P.args, **kwargs: _P.kwargs):
            return await _run_in_main(
                lambda: func(*args, **kwargs), flags=flags
            )

        setattr(wrapped, "_ida_task", True)
        return wrapped

    return decorator


def _make_runner(flags: int):
    async def runner(
        func: ty.Callable[_P, _R], *args: _P.args, **kwargs: _P.kwargs
    ) -> _R:
        return await _run_in_main(lambda: func(*args, **kwargs), flags=flags)

    return runner


def _make_iter(flags: int):
    async def convert_iter(
        iter: ty.Iterator[_R], *, max_items=4096, max_time=0.2
    ) -> ty.AsyncIterator[_R]:
        def read_chunk():
            chunk = list[_R]()
            sliced_iter = islice(iter, max_items)
            start_time = time.monotonic()
            for item in sliced_iter:
                chunk.append(item)
                elapsed = time.monotonic() - start_time
                if elapsed >= max_time:
                    return chunk, True
            return chunk, len(chunk) == max_items

        should_continue = True
        while should_continue:
            chunk, should_continue = await _run_in_main(read_chunk, flags=flags)
            for item in chunk:
                yield item

    return convert_iter


def _make_generator_decorator(flags: int):
    to_async_iter = _make_iter(flags)

    def decorator(
        generator: ty.Callable[_P, ty.Iterator[_R]],
    ) -> ty.Callable[_P, ty.AsyncIterator[_R]]:
        @wraps(generator)
        def wrapped(*args: _P.args, **kwargs: _P.kwargs):
            return to_async_iter(generator(*args, **kwargs))

        setattr(wrapped, "_ida_task", True)
        return wrapped

    return decorator


@ty.overload
def run_sync(
    func: ty.Callable[_P, ty.Awaitable[_R]], *args: _P.args, **kwargs: _P.kwargs
) -> _R: ...


@ty.overload
def run_sync(
    func: ty.Callable[_P, ty.AsyncIterator[_R]],
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> ty.Iterator[_R]: ...


def run_sync(func, *args, **kwargs):
    """
    Run a function wrapped with decorator from this module directly.

    Must be called from IDA's thread.
    """
    assert hasattr(func, "_ida_task"), "Can't run_sync on non-wrapped function"
    return func.__wrapped__(*args, **kwargs)


# Currently we never request MFF_READ, as it proves hard to tell which API only
# reads the DB (e.g. `ida_hexrays.decompile` writes), and getting this wrong may
# lead to crashes.

ui = _make_decorator(ida_kernwin.MFF_FAST)
read = _make_decorator(ida_kernwin.MFF_WRITE)
write = _make_decorator(ida_kernwin.MFF_WRITE)
ui_generator = _make_generator_decorator(ida_kernwin.MFF_FAST)
read_generator = _make_generator_decorator(ida_kernwin.MFF_WRITE)
write_generator = _make_generator_decorator(ida_kernwin.MFF_WRITE)
run_ui = _make_runner(ida_kernwin.MFF_FAST)
run_read = _make_runner(ida_kernwin.MFF_WRITE)
run_write = _make_runner(ida_kernwin.MFF_WRITE)
ui_iter = _make_iter(ida_kernwin.MFF_FAST)
read_iter = _make_iter(ida_kernwin.MFF_WRITE)
write_iter = _make_iter(ida_kernwin.MFF_WRITE)


@dataclass
class _Success(ty.Generic[_R]):
    value: _R


@dataclass
class _Failure:
    ex: Exception


@dataclass
class _Missing:
    pass


async def _run_in_main(func: ty.Callable[[], _R], *, flags: int) -> _R:
    output: ty.Union[_Success, _Failure, _Missing] = _Missing()
    done = anyio.Event()
    cancelled = False
    context = contextvars.copy_context()

    def func_in_task():
        with _set_running_in_task(True):
            return func()

    def perform():
        nonlocal output
        if cancelled:
            return
        try:
            output = _Success(context.run(func_in_task))
        except Exception as ex:
            output = _Failure(ex)
        finally:
            done.set()

    # Use MFF_NOWAIT so event loop is not blocked.
    _execute_sync(perform, flags | ida_kernwin.MFF_NOWAIT)
    try:
        await done.wait()
    except:
        cancelled = True
        raise

    assert isinstance(output, (_Success, _Failure)), "missing output"

    if isinstance(output, _Success):
        return output.value
    elif isinstance(output, _Failure):
        raise output.ex
    else:
        _: tye.Never = output


# Patched in tests.
_execute_sync = ida_kernwin.execute_sync


_P = tye.ParamSpec("_P")


class AsyncCallback(ty.Generic[_P]):
    """
    Allows calling async code from IDA's thread.

    Creation must be done in async context. Calling does not block caller
    thread, only schedules call on event loop.
    """

    _loop: asyncio.AbstractEventLoop
    _context: contextvars.Context
    _callback: ty.Callable[_P, ty.Awaitable[None]]

    def __init__(self, callback: ty.Callable[_P, ty.Awaitable[None]]):
        self._loop = asyncio.get_running_loop()
        self._context = contextvars.copy_context()
        self._callback = callback

    def __call__(self, *args: _P.args, **kwargs: _P.kwargs) -> None:
        async def run():
            await self._context.run(self._callback, *args, **kwargs)

        asyncio.run_coroutine_threadsafe(run(), loop=self._loop)
