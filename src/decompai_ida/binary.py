import gzip
import io
import shutil
import typing as ty
from dataclasses import dataclass

import anyio
import ida_loader
import ida_nalt
import ida_segment
import idautils
from anyio import to_thread

from decompai_ida import ida_tasks


@ida_tasks.read
def get_size() -> int:
    """
    Gets approximate size of the input binary, by summing sizes of segments
    that are mapped to input file.
    """

    def get_mapped_size(segment_start: int) -> int:
        file_offset = ida_loader.get_fileregion_offset(segment_start)
        if file_offset < 0:
            # Not mapped to file (e.g. stack)
            return 0

        segment = ida_segment.getseg(segment_start)
        return segment.size()

    return sum(
        get_mapped_size(segment_start) for segment_start in idautils.Segments()
    )


@ida_tasks.read
def get_binary_path() -> anyio.Path:
    return anyio.Path(ida_nalt.get_input_file_path())


@ida_tasks.read
def get_idb_path() -> anyio.Path:
    return anyio.Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))


@dataclass(frozen=True)
class InputFile:
    name: str
    data: bytes


async def read_compressed_input_file() -> InputFile:
    # Prefer original binary
    input_path = await get_binary_path()
    name = "binary.gz"

    if not await input_path.exists():
        # Fallback to IDB
        input_path = await get_idb_path()
        name = "idb.gz"

    if not await input_path.exists():
        # Give up
        raise Exception("No input file")

    async with await input_path.open("rb") as input_file:
        data = await to_thread.run_sync(
            _compress_gzip, input_file.wrapped, abandon_on_cancel=True
        )

    return InputFile(name=name, data=data)


def _compress_gzip(file_obj: ty.IO[bytes]) -> bytes:
    compressed_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed_buffer, mode="wb") as gz:
        shutil.copyfileobj(file_obj, gz)
    return compressed_buffer.getvalue()
