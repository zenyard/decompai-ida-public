from dataclasses import dataclass
import typing as ty
import ida_funcs
import ida_hexrays
import ida_name
from idaapi import BADADDR
import idautils

from decompai_client import Name
from decompai_client.models import Function, Object, Thunk
from decompai_ida import api, ida_tasks
from decompai_ida.env import Env


@dataclass(frozen=True, kw_only=True)
class ReadFailure:
    address: int
    error: Exception


@ida_tasks.read_generator
def read_objects(
    addresses: ty.Iterable[int],
) -> ty.Iterator[Object | ReadFailure]:
    for address in addresses:
        try:
            yield _read_object_sync(address)
        except Exception as ex:
            yield ReadFailure(address=address, error=ex)


def _read_object_sync(address: int) -> Object:
    """
    Read object at address.

    If `func_graph` is available, it will be used to avoid traversing the
    function for calls.
    """
    state = Env.get().state
    func = ida_funcs.get_func(address)
    assert func is not None
    assert func.start_ea == address

    is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)

    # TODO: maybe we want short/demangled name
    name = ida_name.get_name(address)

    if is_thunk:
        target, _ = ida_funcs.calc_thunk_func_target(func)
        if target == BADADDR:
            raise Exception(f"Can't find thunk target for {address:08x}")

        return Object(
            Thunk(
                address=api.format_address(address),
                name=name,
                target=api.format_address(target),
            )
        )
    else:
        failure = ida_hexrays.hexrays_failure_t()
        decompiled = ida_hexrays.decompile_func(
            func,
            failure,
            ida_hexrays.DECOMP_NO_WAIT,
        )

        if decompiled is None:
            raise Exception(f"Can't decompile {address:08x}: {failure.desc()}")

        code = str(decompiled)
        inferences = state.get_inferences_for_address_sync(address)
        is_named_by_plugin = any(
            isinstance(inference.actual_instance, Name)
            and inference.actual_instance.name in name
            for inference in inferences
        )

        return Object(
            Function(
                address=api.format_address(address),
                name=name,
                code=code,
                calls=_get_calls_sync(address),
                has_known_name=(
                    ida_name.is_uname(name) and not is_named_by_plugin
                ),
            )
        )


def _get_calls_sync(address: int) -> list[str]:
    results = set[int]()
    for item in idautils.FuncItems(address):
        for code_ref in idautils.CodeRefsFrom(item, flow=False):
            func = ida_funcs.get_func(code_ref)
            if func is None or func.start_ea == address:
                continue
            results.add(func.start_ea)
    return [api.format_address(result) for result in results]
