import typing as ty

import exceptiongroup
import ida_funcs
import ida_name
import idc
import typing_extensions as tye

from decompai_client import FunctionOverview, Inference, Name
from decompai_ida import api, ida_tasks, markdown
from decompai_ida.env import Env

_POLL_INTERVAL_SECONDS = 2


def _rgb_to_int(r: int, g: int, b: int) -> int:
    return (b << 16) + (g << 8) + r


_POLL_INTERVAL_SECONDS = 2
_INFERRED_COLOR = _rgb_to_int(220, 202, 255)


@ida_tasks.write
def apply_inferences(inferences: ty.Iterable[Inference]):
    env = Env.get()
    for inference in inferences:
        try:
            inference = _apply_local_transformations(inference)
            if inference.actual_instance is None:
                return
            env.state.add_inference_for_address_sync(
                api.parse_address(inference.actual_instance.address), inference
            )
            if isinstance(inference.actual_instance, FunctionOverview):
                _apply_overview_sync(inference.actual_instance)
            elif isinstance(inference.actual_instance, Name):
                _apply_name_sync(inference.actual_instance)
            else:
                _: tye.Never = inference.actual_instance

        except Exception as ex:
            exceptiongroup.print_exception(ex)


@ida_tasks.write
def clear_inferred_name_marks(address: int):
    current_color = idc.get_color(address, idc.CIC_FUNC)
    if current_color == _INFERRED_COLOR:
        idc.set_color(address, idc.CIC_FUNC, idc.DEFCOLOR)


@ida_tasks.read
def has_user_defined_name(address: int) -> bool:
    """
    Whether given address was named by user (i.e. not inferred or unnamed).
    """

    env = Env.get()

    name = ida_name.get_name(address)
    if not ida_name.is_uname(name):
        # Unnamed.
        return False

    inferences = env.state.get_inferences_for_address_sync(address)
    return not any(
        isinstance(inference.actual_instance, Name)
        and inference.actual_instance.name in name
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
    func = ida_funcs.get_func(address)
    assert func is not None

    ida_funcs.set_func_cmt(func, overview.full_description, False)


def _apply_name_sync(name: Name):
    address = api.parse_address(name.address)

    if ida_tasks.run_sync(has_user_defined_name, address):
        return

    func = ida_funcs.get_func(address)
    assert func is not None
    is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)

    if is_thunk:
        # Let IDA manage names of thunks
        return

    ida_name.set_name(address, name.name, ida_name.SN_FORCE)
    idc.set_color(address, idc.CIC_FUNC, _INFERRED_COLOR)
