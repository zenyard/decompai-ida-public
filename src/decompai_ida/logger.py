from contextlib import asynccontextmanager
from functools import wraps
from io import StringIO
from pathlib import Path
import typing as ty
import exceptiongroup
from structlog.typing import ExcInfo
import typing_extensions as tye
import structlog
import contextvars
import logging


@asynccontextmanager
async def open(log_path: Path, level: ty.Optional[ty.Union[str, int]]):
    if level is None:
        yield
        return

    with log_path.open("a") as log_file:
        logger = _create_logger(log_file, level)
        token = _CURRENT_LOGGER.set(logger)
        try:
            yield
        finally:
            _CURRENT_LOGGER.reset(token)


_R = ty.TypeVar("_R", covariant=True)
_P = tye.ParamSpec("_P")


def instrument(
    **log_kwargs,
) -> ty.Callable[
    [ty.Callable[_P, ty.Awaitable[_R]]], ty.Callable[_P, ty.Awaitable[_R]]
]:
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            with structlog.contextvars.bound_contextvars(**log_kwargs):
                return await func(*args, **kwargs)

        return wrapper

    return decorator


def get() -> structlog.stdlib.BoundLogger:
    return _CURRENT_LOGGER.get()


# Uses exceptiongroup instead of traceback for compatibility with Python 3.9
def _format_exception(exc_info: ExcInfo) -> str:
    sio = StringIO()

    exceptiongroup.print_exception(
        exc_info[0], exc_info[1], exc_info[2], None, sio
    )

    s = sio.getvalue()
    sio.close()
    if s[-1:] == "\n":
        s = s[:-1]

    return s


def _create_logger(
    output: ty.Optional[ty.TextIO], level: ty.Union[str, int]
) -> structlog.stdlib.BoundLogger:
    # Convert level to int for maximum compatibility.
    if isinstance(level, str):
        level = logging.getLevelName(level)

    return structlog.wrap_logger(
        structlog.WriteLogger(output),
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.ExceptionRenderer(_format_exception),
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(
                fmt="%Y-%m-%d %H:%M:%S", utc=False
            ),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        cache_logger_on_first_use=True,
    )


class _NoopLogger:
    def bind(self, **kwargs):
        return self

    def unbind(self, *args, **kwargs):
        return self

    def new(self, *args, **kwargs):
        return self

    def msg(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def warn(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def exception(self, *args, **kwargs):
        pass

    def critical(self, *args, **kwargs):
        pass

    def log(self, *args, **kwargs):
        pass

    async def adebug(self, *args, **kwargs):
        pass

    async def ainfo(self, *args, **kwargs):
        pass

    async def awarning(self, *args, **kwargs):
        pass

    async def awarn(self, *args, **kwargs):
        pass

    async def aerror(self, *args, **kwargs):
        pass

    async def aexception(self, *args, **kwargs):
        pass

    async def acritical(self, *args, **kwargs):
        pass

    async def alog(self, *args, **kwargs):
        pass


_CURRENT_LOGGER = contextvars.ContextVar(
    "decompai_logger",
    default=structlog.wrap_logger(_NoopLogger()),
)
