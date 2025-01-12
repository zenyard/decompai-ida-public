import hashlib
import json
import typing as ty
from dataclasses import dataclass
from itertools import groupby

import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import ida_segment
import idautils
import typing_extensions as tye
from idaapi import BADADDR
from more_itertools import ilen, take

from decompai_client.models import Function, Thunk
from decompai_ida import api, ida_tasks, inferences

_IGNORED_SEGMENTS = {
    "extern",
    ".plt",
    ".plt.got",
    ".got",
    # TODO: PE, Mach-O segments?
}


_MAX_INSTRUCTIONS_TO_DECOMPILE = 0x2000
"""
Skip decompiling functions larger than this. These may cause decompiler to hang for a
long time, and will probably be too large for model.
"""

# An object. The `Object` generated by OpenAPI generator is harder to use since
# it allows for `None`.
Object: tye.TypeAlias = ty.Union[Function, Thunk]


@dataclass(frozen=True)
class ReadObject:
    object: Object
    hash: bytes
    """
    A stable hash of object, useful to test if equal to another.
    """


# Note - decompiling a function actually requires writing to the DB, probably to
# cache results. Using `read` here results in failed decompilations.
@ida_tasks.wrap
def read_object(address: int) -> ReadObject:
    """
    Read object at address.

    If `func_graph` is available, it will be used to avoid traversing the
    function for calls.
    """
    func = ida_funcs.get_func(address)
    assert func is not None
    assert func.start_ea == address

    is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)

    # TODO: maybe we want short/demangled name
    name = ida_name.get_name(address)

    if is_thunk:
        target, _ = ida_funcs.calc_thunk_func_target(func)
        if target == BADADDR:
            raise Exception("Can't find thunk target")

        obj = Thunk(
            address=api.format_address(address),
            name=name,
            target=api.format_address(target),
        )
        hashed_obj = obj

    else:
        if _is_too_big_to_decompile(address):
            raise Exception("Not decompiling, too big")

        failure = ida_hexrays.hexrays_failure_t()
        decompiled = ida_hexrays.decompile_func(
            func,
            failure,
            ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_NO_CACHE,
        )

        if decompiled is None:
            raise Exception(f"Can't decompile: {failure.desc()}")
        code = str(decompiled)
        reducted_code = _get_reducted_code_sync(decompiled)

        has_known_name = inferences.has_user_defined_name.sync(address)

        obj = Function(
            address=api.format_address(address),
            name=name,
            code=code,
            calls=_get_calls_sync(address),
            has_known_name=has_known_name,
        )

        hashed_obj = Function(
            address=obj.address,
            name=obj.name,
            code=reducted_code,
            calls=obj.calls,
            has_known_name=obj.has_known_name,
        )

    return ReadObject(object=obj, hash=_hash_object(hashed_obj))


@ida_tasks.wrap
def is_in_ignored_segment(address: int) -> bool:
    segment = ida_segment.getseg(address)

    if ida_segment.get_segm_class(segment) != "CODE":
        return True

    if ida_segment.get_segm_name(segment) in _IGNORED_SEGMENTS:
        return True

    return False


def _hash_object(obj: Object) -> bytes:
    data = json.dumps(
        obj.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.blake2b(data, digest_size=8).digest()


def _get_calls_sync(address: int) -> list[str]:
    results = set[int]()
    for item in idautils.FuncItems(address):
        for code_ref in idautils.CodeRefsFrom(item, flow=False):
            func = ida_funcs.get_func(code_ref)
            if func is None or func.start_ea == address:
                continue
            results.add(func.start_ea)
    return [api.format_address(result) for result in results]


def _is_too_big_to_decompile(address: int) -> int:
    return (
        ilen(take(_MAX_INSTRUCTIONS_TO_DECOMPILE, idautils.FuncItems(address)))
        == _MAX_INSTRUCTIONS_TO_DECOMPILE
    )


_CFunc: tye.TypeAlias = ty.Union[ida_hexrays.cfunc_t, ida_hexrays.cfuncptr_t]


def _get_reducted_code_sync(func: _CFunc):
    """
    Gets code but replaces all references to other objects with `[obj]`.

    This is useful for hashing, so that changing other objects doesn't change
    change of this object.
    """
    code = list[str]()

    for text_part, address in _text_parts_and_addresses_sync(func):
        if (
            address is not None
            and address != func.entry_ea  # type: ignore
            and _is_object_address_sync(address)
        ):
            code.append("[obj]")
        else:
            code.append(text_part)

    return "".join(code)


def _text_parts_and_addresses_sync(
    func: _CFunc,
) -> ty.Iterator[tuple[str, ty.Optional[int]]]:
    for address, tags in groupby(
        _chars_and_addresses_sync(func), lambda pair: pair[1]
    ):
        text = "".join(text for text, _ in tags)
        yield text, address


def _chars_and_addresses_sync(
    func: _CFunc,
) -> ty.Iterator[tuple[str, ty.Optional[int]]]:
    ctree_item = ida_hexrays.ctree_item_t()
    for line in func.get_pseudocode():
        line = line.line
        text = _remove_codes_sync(line)
        for i in range(len(text)):
            success = func.get_line_item(line, i, True, None, ctree_item, None)  # type: ignore

            if success:
                address = ctree_item.get_ea()
                if address == BADADDR:
                    address = None
            else:
                address = None

            yield text[i], address

        yield "\n", None


def _remove_codes_sync(text: str) -> str:
    output = list[str]()
    i = 0
    while i < len(text):
        tag_length = ida_lines.tag_advance(text[i:], 1)
        codes_length = ida_lines.tag_skipcodes(text[i:])
        output.append(text[i + codes_length : i + tag_length])
        i += tag_length
    return "".join(output)


def _is_object_address_sync(address: int) -> bool:
    func = ida_funcs.get_func(address)

    if func is None or address != func.start_ea:
        return False

    if is_in_ignored_segment.sync(address):
        return False

    return True
