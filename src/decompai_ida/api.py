import typing as ty
from asyncio.exceptions import TimeoutError

import anyio
import typing_extensions as tye
from aiohttp.client_exceptions import ClientConnectionError

from decompai_client import (
    ApiClient,
)
from decompai_client import (
    Configuration as ApiConfiguration,
)
from decompai_client.exceptions import ServiceException
from decompai_ida import status
from decompai_ida.configuration import PluginConfiguration

_RETRY_DELAY = 3

_T = ty.TypeVar("_T")
_P = tye.ParamSpec("_P")


def get_api_client(plugin_config: PluginConfiguration) -> ApiClient:
    return ApiClient(
        ApiConfiguration(
            host=str(plugin_config.api_url).rstrip("/"),
            api_key={"APIKeyHeader": plugin_config.api_key},
        )
    )


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
                await task.set_warning()
                await anyio.sleep(_RETRY_DELAY)
            else:
                raise


def parse_address(api_address: str) -> int:
    return int(api_address, 16)


def format_address(address: int) -> str:
    return f"{address:016x}"
