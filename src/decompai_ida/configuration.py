import typing as ty
from pathlib import Path

import anyio
import ida_diskio
from pydantic import BaseModel, StringConstraints, UrlConstraints
from pydantic_core import Url

from decompai_ida import ida_tasks

_CONFIG_FILENAME = "decompai.json"


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

    require_confirmation_per_db: bool = False


async def read_configuration() -> PluginConfiguration:
    config_path = await get_config_path()

    try:
        async with await anyio.open_file(config_path) as config_file:
            return PluginConfiguration.model_validate_json(
                await config_file.read()
            )

    except Exception:
        raise BadConfigurationFile(config_path)


@ida_tasks.wrap
def get_config_path() -> Path:
    return Path(ida_diskio.get_user_idadir()) / _CONFIG_FILENAME
