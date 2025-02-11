"""
Allows running code that accesses IDA's API from async.

Utilities:
- `wrap` - decorator for converting sync code to async.
- `wrap_generator` - decorator for converting sync generator to async generator.
- `run` - call a sync function from async.
- `run_ui` - modify UI from async.
- `wrap_iterator` - turn iterator to async iterator (useful with idautils).
- `for_each` - apply sync function on each element from async.
- `AsyncCallback` - make async function callable from sync.
- `hook` - apply IDA hooks from async.

Decorators are currently not suitable for methods. Decorated functions offer
their original counterpart under `sync` method.
"""

import asyncio
import contextvars
import time
import typing as ty
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from functools import wraps
from itertools import islice

import anyio
import ida_kernwin
import typing_extensions as tye

_T = ty.TypeVar("_T")
_R = ty.TypeVar("_R", covariant=True)
_P = tye.ParamSpec("_P")

_running_in_task = contextvars.ContextVar("running_in_task", default=False)


class WrappedFunc(ty.Protocol, ty.Generic[_P, _R]):
    async def __call__(self, *args: _P.args, **kwargs: _P.kwargs) -> _R: ...
    def sync(self, *args: _P.args, **kwargs: _P.kwargs) -> _R: ...


class WrappedGenerator(ty.Protocol, ty.Generic[_P, _R]):
    def __call__(
        self, *args: _P.args, **kwargs: _P.kwargs
    ) -> ty.AsyncIterator[_R]: ...
    def sync(self, *args: _P.args, **kwargs: _P.kwargs) -> ty.Iterator[_R]: ...


def is_running_in_task() -> bool:
    "Whether calling code runs on task invoked by this module"
    return _running_in_task.get()


def assert_running_in_task():
    """
    Raises if called outside task (outside IDA's thread).

    Should be added to all functions not explicitly wrapped with a decorator
    from this module. Decorators add this check to their `sync` variant.
    """
    assert is_running_in_task(), "Sync code running outside task"


@contextmanager
def _set_running_in_task(value: bool):
    token = _running_in_task.set(value)
    try:
        yield
    finally:
        _running_in_task.reset(token)


@ty.overload
def wrap(
    *, ui_only: bool
) -> ty.Callable[[ty.Callable[_P, _R]], WrappedFunc[_P, _R]]: ...


@ty.overload
def wrap(func: ty.Callable[_P, _R], /) -> WrappedFunc[_P, _R]: ...


def wrap(
    func: ty.Optional[ty.Callable[_P, _R]] = None, *, ui_only=False
) -> ty.Any:
    def wrapper(func: ty.Callable[_P, _R]) -> WrappedFunc[_P, _R]:
        @wraps(func)
        def wrapped_with_assert(*args: _P.args, **kwargs: _P.kwargs):
            assert_running_in_task()
            return func(*args, **kwargs)

        @wraps(func)
        async def wrapped(*args: _P.args, **kwargs: _P.kwargs):
            return await _run_in_main(
                lambda: func(*args, **kwargs),
                ida_kernwin.MFF_FAST if ui_only else ida_kernwin.MFF_WRITE,
            )

        setattr(wrapped, "sync", wrapped_with_assert)
        return ty.cast(ty.Any, wrapped)

    if func is not None:
        return wrapper(func)
    else:
        return wrapper


async def run(
    func: ty.Callable[_P, _R], *args: _P.args, **kwargs: _P.kwargs
) -> _R:
    return await _run_in_main(lambda: func(*args, **kwargs))


async def run_ui(
    func: ty.Callable[_P, _R], *args: _P.args, **kwargs: _P.kwargs
) -> _R:
    """
    Like `run`, but function is called sooner and without access to DB.

    Only suitable for updating UI.
    """
    return await _run_in_main(
        lambda: func(*args, **kwargs), flags=ida_kernwin.MFF_FAST
    )


async def wrap_iter(
    iter: ty.Iterator[_R],
    *,
    max_items=1024,
    max_time=0.010,
    sleep_between=0.005,
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
        chunk, should_continue = await _run_in_main(read_chunk)
        for item in chunk:
            yield item
        if should_continue and sleep_between > 0:
            await anyio.sleep(sleep_between)


def wrap_generator(
    generator: ty.Callable[_P, ty.Iterator[_R]],
) -> WrappedGenerator[_P, _R]:
    @wraps(generator)
    def wrapped_with_assert(*args: _P.args, **kwargs: _P.kwargs):
        for item in generator(*args, **kwargs):
            assert_running_in_task()
            yield item

    @wraps(generator)
    def wrapped(*args: _P.args, **kwargs: _P.kwargs):
        return wrap_iter(generator(*args, **kwargs))

    setattr(wrapped, "sync", wrapped_with_assert)
    return ty.cast(ty.Any, wrapped)


async def for_each(
    iterable: ty.Iterable[_T],
    func: ty.Callable[[_T], None],
) -> None:
    async for _ in wrap_iter(func(item) for item in iterable):
        pass


@dataclass
class _Success(ty.Generic[_R]):
    value: _R


@dataclass
class _Failure:
    ex: Exception


@dataclass
class _Missing:
    pass


async def _run_in_main(
    func: ty.Callable[[], _R], flags=ida_kernwin.MFF_WRITE
) -> _R:
    output: ty.Union[_Success, _Failure, _Missing] = _Missing()
    done = anyio.Event()
    set_done = AsyncCallback(done.set)
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
            set_done()

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
    _callback: ty.Callable[_P, ty.Union[ty.Awaitable[None], None]]

    def __init__(
        self, callback: ty.Callable[_P, ty.Union[ty.Awaitable[None], None]]
    ):
        self._loop = asyncio.get_running_loop()
        self._context = contextvars.copy_context()
        self._callback = callback

    def __call__(self, *args: _P.args, **kwargs: _P.kwargs) -> None:
        async def run():
            result = self._context.run(self._callback, *args, **kwargs)
            if result is not None:
                await result

        asyncio.run_coroutine_threadsafe(run(), loop=self._loop)


class _Hooks(ty.Protocol):
    def hook(self) -> bool: ...
    def unhook(self) -> bool: ...


@asynccontextmanager
async def hook(hooks: _Hooks):
    success = await run_ui(hooks.hook)
    if not success:
        raise Exception(f"Hooking {hooks} failed")
    try:
        yield
    finally:
        success = await run_ui(hooks.unhook)
        if not success:
            raise Exception(f"Unhooking {hooks} failed")
