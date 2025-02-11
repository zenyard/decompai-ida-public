import typing as ty
from inspect import cleandoc
from pathlib import Path

import ida_diskio
import ida_kernwin
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

    log_level: ty.Optional[
        ty.Literal[
            "CRITICAL",
            "FATAL",
            "ERROR",
            "WARN",
            "WARNING",
            "INFO",
            "DEBUG",
        ]
    ] = None

    def with_user_config(
        self, *, require_confirmation_per_db: bool
    ) -> "PluginConfiguration":
        return PluginConfiguration(
            api_url=self.api_url,
            api_key=self.api_key,
            require_confirmation_per_db=require_confirmation_per_db,
            log_level=self.log_level,
        )


@ida_tasks.wrap
def read_configuration() -> PluginConfiguration:
    config_path = get_config_path.sync()

    try:
        with config_path.open() as config_file:
            return PluginConfiguration.model_validate_json(config_file.read())

    except Exception:
        raise BadConfigurationFile(config_path)


@ida_tasks.wrap
def get_config_path() -> Path:
    return Path(ida_diskio.get_user_idadir()) / _CONFIG_FILENAME


@ida_tasks.wrap
def show_configuration_dialog():
    FORM_DEFINITION = cleandoc("""
        DecompAI settings

        <Ask before running DecompAI on files opened for the first time.:C>>
    """)
    REQUIRE_CONFIRMATION_FLAG = 1 << 0

    current_config = read_configuration.sync()

    checkboxes = ida_kernwin.Form.NumericArgument(  # type: ignore
        ida_kernwin.Form.FT_UINT64,
        (
            REQUIRE_CONFIRMATION_FLAG
            if current_config.require_confirmation_per_db
            else 0
        ),
    )

    result = ida_kernwin.ask_form(FORM_DEFINITION, checkboxes.arg)

    if result != ida_kernwin.ASKBTN_YES:
        return

    new_config = current_config.with_user_config(
        require_confirmation_per_db=(
            checkboxes.value & REQUIRE_CONFIRMATION_FLAG
        ),
    )

    config_path = get_config_path.sync()
    with config_path.open("w") as config_file:
        config_file.write(new_config.model_dump_json(indent=4))
