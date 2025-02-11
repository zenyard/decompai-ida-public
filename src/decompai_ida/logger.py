from contextlib import asynccontextmanager
from functools import wraps
from pathlib import Path
import typing as ty
import typing_extensions as tye
import structlog
import contextvars


@asynccontextmanager
async def open(log_path: Path, level: ty.Optional[str]):
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


def _create_logger(
    output: ty.Optional[ty.TextIO], level: str
) -> structlog.stdlib.BoundLogger:
    return structlog.wrap_logger(
        structlog.WriteLogger(output),
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
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


_CURRENT_LOGGER = contextvars.ContextVar(
    "decompai_logger",
    default=_create_logger(None, "CRITICAL"),
)
