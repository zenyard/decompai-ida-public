# ruff: noqa
import site
from pathlib import Path

DECOMPAI_PACKAGES = Path(__file__).parent / "decompai_packages"
if DECOMPAI_PACKAGES.is_dir():
    site.addsitedir(str(DECOMPAI_PACKAGES))

from decompai_ida.plugin import PLUGIN_ENTRY, DecompaiPlugin
