import colorsys
import typing as ty

import exceptiongroup
import ida_funcs
import ida_name
import idc

from decompai_client import FunctionOverview, Inference, Name
from decompai_ida import api, ida_tasks
from decompai_ida.env import Env

_POLL_INTERVAL_SECONDS = 2

# HSV values to use for colors. "Best" / "worst" according to confidence.
_BEST_COLOR_H = 110
_WORST_COLOR_H = 40
_COLOR_S = 36
_COLOR_V = 255


@ida_tasks.write
def apply_inferences(inferences: ty.Iterable[Inference]):
    for inference in inferences:
        try:
            env = Env.get()
            if inference.actual_instance is None:
                return
            env.state.add_inference_for_address_sync(
                api.parse_address(inference.actual_instance.address), inference
            )
            match inference.actual_instance:
                case FunctionOverview() as overview:
                    _apply_overview_sync(overview)
                case Name() as name:
                    _apply_name_sync(name)
        except Exception as ex:
            exceptiongroup.print_exception(ex)


def _apply_overview_sync(overview: FunctionOverview):
    address = api.parse_address(overview.address)
    func = ida_funcs.get_func(address)
    assert func is not None

    confidence = overview.confidence

    ida_funcs.set_func_cmt(func, overview.full_description, False)
    idc.set_color(address, idc.CIC_FUNC, _color_for_confidence(confidence))


def _apply_name_sync(name: Name):
    address = api.parse_address(name.address)
    func = ida_funcs.get_func(address)
    assert func is not None
    is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)

    if is_thunk:
        # Let IDA manage names of thunks
        return

    ida_name.set_name(address, name.name, ida_name.SN_FORCE)


def _color_for_confidence(confidence: int) -> int:
    if confidence < 1:
        confidence = 1
    elif confidence > 5:
        confidence = 5

    h_step = (_BEST_COLOR_H - _WORST_COLOR_H) / 4

    return _rgb_to_int(
        colorsys.hsv_to_rgb(
            (_WORST_COLOR_H + (confidence - 1) * h_step) / 359,
            _COLOR_S / 255,
            _COLOR_V / 255,
        )
    )


def _rgb_to_int(rgb: tuple[float, float, float]) -> int:
    r, g, b = rgb
    return (int(b * 255) << 16) + (int(g * 255) << 8) + int(r * 255)
