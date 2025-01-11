import typing as ty
from contextlib import contextmanager

import exceptiongroup
import ida_funcs
import ida_name
import idc
import typing_extensions as tye
from anyio import TASK_STATUS_IGNORED
from anyio.abc import TaskStatus

from decompai_client import FunctionOverview, Inference, Name
from decompai_ida import api, ida_tasks, markdown, objects, state
from decompai_ida.env import Env

_POLL_INTERVAL_SECONDS = 2


def _rgb_to_int(r: int, g: int, b: int) -> int:
    return (b << 16) + (g << 8) + r


_POLL_INTERVAL_SECONDS = 2
_INFERRED_COLOR = _rgb_to_int(220, 202, 255)


@ida_tasks.wrap
def apply_inferences(inferences: ty.Iterable[Inference]):
    for inference in inferences:
        try:
            inference = _apply_local_transformations(inference)
            if inference.actual_instance is None:
                return
            address = api.parse_address(inference.actual_instance.address)
            state.add_inference_for_address.sync(address, inference)

            with _maintain_uploaded_hash_sync(address):
                if isinstance(inference.actual_instance, FunctionOverview):
                    _apply_overview_sync(inference.actual_instance)
                elif isinstance(inference.actual_instance, Name):
                    _apply_name_sync(inference.actual_instance)
                else:
                    _: tye.Never = inference.actual_instance

        except Exception as ex:
            exceptiongroup.print_exception(ex)


async def clear_inferences_marks_task(
    *, task_status: TaskStatus[None] = TASK_STATUS_IGNORED
):
    env = Env.get()

    async with env.check_addresses.subscribe() as check_addresses_receiver:
        async for check_addresses in check_addresses_receiver:
            await ida_tasks.for_each(
                check_addresses.addresses, _clear_inferred_name_marks_sync
            )


def _clear_inferred_name_marks_sync(address: int):
    func = ida_funcs.get_func(address)
    if func is None or address != func.start_ea:
        return

    if idc.get_color(address, idc.CIC_FUNC) == _INFERRED_COLOR:
        return

    if not has_user_defined_name.sync(address):
        return

    idc.set_color(address, idc.CIC_FUNC, idc.DEFCOLOR)


@ida_tasks.wrap
def has_user_defined_name(address: int) -> bool:
    """
    Whether given address was named by user (i.e. not inferred or unnamed).
    """

    name = ida_name.get_name(address)
    if not ida_name.is_uname(name):
        # Unnamed.
        return False

    inferences = state.get_inferences_for_address.sync(address)
    return not any(
        isinstance(inference.actual_instance, Name)
        and inference.actual_instance.name in name
        for inference in inferences
    )


@ida_tasks.wrap
def has_user_defined_comment(address: int) -> bool:
    """
    Whether given address has function comment given by user.
    """

    func = ida_funcs.get_func(address)
    if func is None:
        return False

    comment = ida_funcs.get_func_cmt(func, False) or ida_funcs.get_func_cmt(
        func, True
    )
    if comment is None:
        return False

    comment = comment.strip()
    if len(comment) == 0:
        return False

    inferences = state.get_inferences_for_address.sync(address)
    return not any(
        isinstance(inference.actual_instance, FunctionOverview)
        and inference.actual_instance.full_description.strip() == comment
        for inference in inferences
    )


def _apply_local_transformations(inference: Inference) -> Inference:
    if isinstance(inference.actual_instance, FunctionOverview):
        overview = inference.actual_instance
        return Inference(
            overview.model_copy(
                update={
                    "full_description": markdown.format(
                        overview.full_description
                    )
                }
            )
        )
    else:
        return inference


def _apply_overview_sync(overview: FunctionOverview):
    address = api.parse_address(overview.address)

    if has_user_defined_comment.sync(address):
        return

    func = ida_funcs.get_func(address)
    assert func is not None

    ida_funcs.set_func_cmt(func, overview.full_description, False)


def _apply_name_sync(name: Name):
    address = api.parse_address(name.address)

    if has_user_defined_name.sync(address):
        return

    func = ida_funcs.get_func(address)
    assert func is not None
    is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)

    if is_thunk:
        # Let IDA manage names of thunks
        return

    ida_name.set_name(address, name.name, ida_name.SN_FORCE)
    idc.set_color(address, idc.CIC_FUNC, _INFERRED_COLOR)


@contextmanager
def _maintain_uploaded_hash_sync(address: int):
    """
    If object before changes is synced with server (according to hash),
    update the hash once context exists.

    This is for doing changes the we know the server emulates (i.e. applying
    inferences), so the uploaded hash can reflect server's emulated state.
    """

    try:
        original_hash = objects.read_object.sync(address).hash
    except Exception:
        original_hash = None

    try:
        yield

    finally:
        if original_hash is None:
            return

        sync_status = state.get_sync_status.sync(address)
        if original_hash == sync_status.uploaded_hash:
            try:
                updated_hash = objects.read_object.sync(address).hash
                state.set_sync_status.sync(
                    address,
                    sync_status.with_uploaded_hash(updated_hash),
                )

            except Exception:
                pass
