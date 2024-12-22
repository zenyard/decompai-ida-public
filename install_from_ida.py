# Quick installation from IDA, based on:
#   https://github.com/eset/ipyida/blob/master/install_from_ida.py

import json
import shutil
import subprocess
import sys
import threading
from types import EllipsisType
import typing as ty
from pathlib import Path
from textwrap import indent
from urllib.request import urlopen
from uuid import UUID

import ida_diskio
import ida_kernwin
import ida_loader

API_URL = "https://api.zenyard.ai"
INSTALL_LOCATION = "git+https://github.com/zenyard/decompai-ida-public.git"
STUB_FILE_URL = "https://raw.githubusercontent.com/zenyard/decompai-ida-public/main/decompai_stub.py"

user_dir = Path(ida_diskio.get_user_idadir())
stub_path = user_dir / "plugins" / "decompai_stub.py"
packages_path = user_dir / "plugins" / "decompai_packages"
config_path = user_dir / "decompai.json"


def main():
    try:
        config_exists = stub_path.exists()

        check_prerequisites()

        if not config_exists:
            api_key = request_api_key()
        else:
            print("[+] Will use existing API key")
            api_key = None

        print("[+] Installing or upgrading package (may take a minute)")
        install_or_upgrade_package(INSTALL_LOCATION, target=packages_path)

        print("[+] Installing plugin stub file")
        install_stub_file()

        if not config_exists:
            print("[+] Installing API key")
            assert api_key is not None
            install_configuration(api_key=api_key)

        print("[+] All set!")
        run_in_ui(lambda: ida_loader.load_plugin(str(stub_path)))

    except Exception as ex:
        message = f"Install failed: {ex}"
        run_in_ui(lambda: ida_kernwin.warning(message))


def check_prerequisites():
    if sys.version_info < (3, 10):
        raise Exception(f"Python 3.10 or higher required, got {sys.version}")

    ida_version = run_in_ui(ida_kernwin.get_kernel_version)
    ida_major = int(ida_version.split(".")[0])
    if ida_major < 9:
        raise Exception("IDA 9.0 or higher required")

    if shutil.which("git") is None:
        raise Exception("Git is required for installation")

    try:
        import pip  # type: ignore  # noqa: F401
    except ImportError:
        raise Exception("Pip is required for installation")


def request_api_key():
    api_key = run_in_ui(
        lambda: ida_kernwin.ask_text(
            36, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "Enter API key"
        )
    )

    if api_key is None:
        raise Exception("No API key entered")

    try:
        api_key = str(UUID(api_key.strip()))
    except ValueError:
        raise Exception("Invalid API key")

    return api_key


def get_hidden_window_startupinfo():
    if sys.platform == "win32":
        si_hidden_window = subprocess.STARTUPINFO()
        si_hidden_window.dwFlags = subprocess.STARTF_USESHOWWINDOW
        si_hidden_window.wShowWindow = subprocess.SW_HIDE
        return si_hidden_window
    else:
        return None


def install_or_upgrade_package(source: str, *, target: Path):
    # Try again as user
    try:
        run_pip(("install", "--upgrade", "--target", str(target), source))
    except subprocess.CalledProcessError as ex:
        all_output = indent(
            "\n".join((ex.stdout, ex.stderr)).strip(),
            prefix="[pip] ",
            predicate=lambda line: True,
        )
        print(all_output)
        raise


def run_pip(args: ty.Iterable[str]):
    subprocess.run(
        [python_executable(), "-m", "pip", *args],
        startupinfo=get_hidden_window_startupinfo(),
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )


def python_executable() -> Path:
    base_path = Path(sys.prefix)
    if sys.platform == "win32":
        exe_path_venv = base_path / "Scripts" / "Python.exe"
        executable = (
            exe_path_venv
            if exe_path_venv.exists()
            else base_path / "Python.exe"
        )
    else:
        executable = base_path / "bin" / f"python{sys.version_info.major}"
    return executable


def install_stub_file():
    stub_path.parent.mkdir(parents=True, exist_ok=True)

    with (
        urlopen(STUB_FILE_URL) as remote_input,
        stub_path.open("wb") as local_output,
    ):
        shutil.copyfileobj(remote_input, local_output)


def install_configuration(*, api_key: str):
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with config_path.open("w") as config_output:
        json.dump({"api_url": API_URL, "api_key": api_key}, config_output)


T = ty.TypeVar("T")


def run_in_ui(func: ty.Callable[[], T]) -> T:
    output: EllipsisType | T = ...
    error: Exception | None = None

    def perform():
        nonlocal output, error
        try:
            output = func()
        except Exception as ex:
            error = ex

    ida_kernwin.execute_sync(perform, ida_kernwin.MFF_FAST)

    if error is not None:
        raise error
    else:
        assert not isinstance(output, EllipsisType)
        return output


if __name__ == "__main__":
    threading.Thread(target=main).start()
