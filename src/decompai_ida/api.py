import typing as ty
from pathlib import Path
from aiohttp.client_exceptions import ClientConnectionError
from asyncio.exceptions import TimeoutError

import anyio
import ida_diskio
from pydantic import BaseModel, StringConstraints, UrlConstraints
from pydantic_core import Url

from decompai_client import (
    ApiClient,
    Configuration as ApiConfiguration,
)
from decompai_client.exceptions import ServiceException
from decompai_ida import ida_tasks, status

_CONFIG_FILENAME = "decompai.json"
_RETRY_DELAY = 3

_T = ty.TypeVar("_T")
_P = ty.ParamSpec("_P")


class BadConfigurationFile(Exception):
    def __init__(self, config_path: Path):
        super().__init__(f"Missing or bad configuration file at {config_path}")


class PluginConfiguration(BaseModel, frozen=True):
    api_url: ty.Annotated[
        Url,
        UrlConstraints(
            allowed_schemes=["http", "https"],
            host_required=True,
            max_length=2048,
        ),
    ]
    api_key: ty.Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=2048),
    ]


async def get_api_client() -> ApiClient:
    config_path = await get_config_path()

    try:
        async with await anyio.open_file(config_path) as config_file:
            plugin_config = PluginConfiguration.model_validate_json(
                await config_file.read()
            )
    except Exception:
        raise BadConfigurationFile(config_path)

    return ApiClient(
        ApiConfiguration(
            host=str(plugin_config.api_url).rstrip("/"),
            api_key={"APIKeyHeader": plugin_config.api_key},
        )
    )


@ida_tasks.ui
def get_config_path() -> Path:
    return Path(ida_diskio.get_user_idadir()) / _CONFIG_FILENAME


def is_temporary_error(error: Exception):
    """
    True for network and server side (500) errors.
    """
    return isinstance(
        error, (ClientConnectionError, ServiceException, TimeoutError)
    )


async def retry_forever(
    func: ty.Callable[[], ty.Awaitable[_T]],
    *,
    task: status.Task,
) -> _T:
    while True:
        try:
            result = await func()
            await task.clear_warning()
            return result
        except Exception as ex:
            if is_temporary_error(ex):
                await task.set_warning("Can't reach server")
                await anyio.sleep(_RETRY_DELAY)
            else:
                raise


def parse_address(api_address: str) -> int:
    return int(api_address, 16)


def format_address(address: int) -> str:
    return f"{address:016x}"
