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
from contextlib import contextmanager
import contextvars
import time
import typing as ty
from dataclasses import dataclass
from itertools import islice

import anyio
import ida_kernwin

_T = ty.TypeVar("_T")
_P = ty.ParamSpec("_P")

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
        func: ty.Callable[_P, _T],
    ) -> ty.Callable[_P, ty.Awaitable[_T]]:
        async def wrapped(*args: _P.args, **kwargs: _P.kwargs):
            return await _run_in_main(
                lambda: func(*args, **kwargs), flags=flags
            )

        return wrapped

    return decorator


def _make_runner(flags: int):
    async def runner(
        func: ty.Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs
    ) -> _T:
        return await _run_in_main(lambda: func(*args, **kwargs), flags=flags)

    return runner


def _make_iter(flags: int):
    async def convert_iter(
        iter: ty.Iterator[_T], *, max_items=4096, max_time=0.2
    ) -> ty.AsyncIterator[_T]:
        def read_chunk():
            chunk = list[_T]()
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
        generator: ty.Callable[_P, ty.Iterator[_T]],
    ) -> ty.Callable[_P, ty.AsyncIterator[_T]]:
        def wrapped(*args: _P.args, **kwargs: _P.kwargs):
            return to_async_iter(generator(*args, **kwargs))

        return wrapped

    return decorator


ui = _make_decorator(ida_kernwin.MFF_FAST)
read = _make_decorator(ida_kernwin.MFF_READ)
write = _make_decorator(ida_kernwin.MFF_WRITE)
ui_generator = _make_generator_decorator(ida_kernwin.MFF_FAST)
read_generator = _make_generator_decorator(ida_kernwin.MFF_READ)
write_generator = _make_generator_decorator(ida_kernwin.MFF_WRITE)
run_ui = _make_runner(ida_kernwin.MFF_FAST)
run_read = _make_runner(ida_kernwin.MFF_READ)
run_write = _make_runner(ida_kernwin.MFF_WRITE)
ui_iter = _make_iter(ida_kernwin.MFF_FAST)
read_iter = _make_iter(ida_kernwin.MFF_READ)
write_iter = _make_iter(ida_kernwin.MFF_WRITE)


@dataclass
class _Success(ty.Generic[_T]):
    value: _T


@dataclass
class _Failure:
    value: Exception


@dataclass
class _Missing:
    pass


async def _run_in_main(func: ty.Callable[[], _T], *, flags: int) -> _T:
    output: _Success | _Failure | _Missing = _Missing()
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
    ida_kernwin.execute_sync(perform, flags | ida_kernwin.MFF_NOWAIT)
    try:
        await done.wait()
    except:
        cancelled = True
        raise

    assert not isinstance(output, _Missing), "missing output"

    match output:
        case _Success(value):
            return value
        case _Failure(ex):
            raise ex


_P = ty.ParamSpec("_P")


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
