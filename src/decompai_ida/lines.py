"""
Helpers to parse `ida_lines` format.
"""

from dataclasses import dataclass
import re
import typing as ty
from itertools import groupby

import ida_hexrays
import ida_lines
import ida_name
import typing_extensions as tye
from idaapi import BADADDR
from more_itertools import before_and_after, peekable

from decompai_client import AddressDetail, LVarDetail, Range, RangeDetail
from decompai_ida import api, ida_tasks

_CFunc: tye.TypeAlias = ty.Union[ida_hexrays.cfunc_t, ida_hexrays.cfuncptr_t]
_IDENTIFIER_PATTERN = re.compile(r"(?!\d)\w+")


@ida_tasks.wrap_generator
def get_ranges(func: _CFunc) -> ty.Iterator[Range]:
    current_line_index = 0

    func_lines = _FuncLines.from_func_sync(func)  # type: ignore
    arg_names: set[str] = {lvar.name for lvar in func.lvars if lvar.is_arg_var}  # type: ignore

    for line in func_lines.comment:
        current_line_index += len(_strip_codes(line)) + 1

    for line in func_lines.signature:
        for range in _arg_lvar_ranges(line, arg_names):
            yield _offset_range(range, current_line_index)
        current_line_index += len(_strip_codes(line)) + 1

    for line in func_lines.body:
        for range in _parse_ranges_sync(func, line):
            for narrowed_range in _narrow_range(line, range):
                yield _offset_range(narrowed_range, current_line_index)
        current_line_index += len(_strip_codes(line)) + 1


def _offset_range(range: Range, offset: int) -> Range:
    return Range(
        start=range.start + offset,
        length=range.length,
        detail=range.detail,
    )


def _parse_ranges_sync(func: _CFunc, line: str) -> ty.Iterator[Range]:
    ida_tasks.assert_running_in_task()

    ctree_item = ida_hexrays.ctree_item_t()

    def pos_and_tags():
        pos = 0
        for _, tag_text in _tags_sync(line):
            yield pos, tag_text
            pos += len(tag_text)

    def detail_at(i: int) -> ty.Optional[RangeDetail]:
        func.get_line_item(
            line,
            i,
            True,
            None,  # type: ignore
            ctree_item,
            None,  # type: ignore
        )
        return _detail_from_ctree_item_sync(ctree_item)

    tags_and_details = (
        (pos, tag, detail_at(pos)) for pos, tag in pos_and_tags()
    )
    tag_runs = groupby(tags_and_details, lambda pair: pair[2])

    for detail, tags_and_details in tag_runs:
        if detail is not None:
            tags_and_details = peekable(tags_and_details)
            start, _, _ = tags_and_details.peek()
            length = sum(len(tag) for _, tag, _ in tags_and_details)
            yield Range(start=start, length=length, detail=detail)


def _strip_codes(text: str) -> str:
    return "".join(tag_text for _, tag_text in _tags_sync(text))


def _tags_sync(text: str) -> ty.Iterable[tuple[str, str]]:
    ida_tasks.assert_running_in_task()

    i = 0
    while i < len(text):
        tag_length = ida_lines.tag_advance(text[i:], 1)
        codes_length = ida_lines.tag_skipcodes(text[i:])
        tag_codes = text[i : i + codes_length]
        tag_text = text[i + codes_length : i + tag_length]
        yield tag_codes, tag_text
        i += tag_length


def _detail_from_ctree_item_sync(
    ctree_item: ida_hexrays.ctree_item_t,
) -> ty.Optional[RangeDetail]:
    ida_tasks.assert_running_in_task()

    address = ctree_item.get_ea()
    if address != BADADDR:
        return RangeDetail(AddressDetail(address=api.format_address(address)))

    lvar = ctree_item.get_lvar()
    if lvar is not None:
        return RangeDetail(
            LVarDetail(name=lvar.name, is_arg=lvar.is_arg_var)  # type: ignore
        )


_NAME_PATTERN = re.compile(r"\b[a-z_]\w*", re.IGNORECASE)


def _narrow_range(line: str, range: Range) -> ty.Iterator[Range]:
    if range.detail is None:
        yield range
        return

    detail = range.detail.actual_instance
    assert detail is not None

    if isinstance(detail, AddressDetail):
        address_name = ida_name.get_short_name(
            api.parse_address(detail.address)
        )
        yield from _narrow_when_name_is(line, range, address_name)
    elif isinstance(detail, LVarDetail):
        lvar_name = detail.name
        yield from _narrow_when_name_is(line, range, lvar_name)
    else:
        _: tye.Never = detail


def _narrow_when_name_is(
    line: str, range: Range, name: ty.Optional[str] = None
) -> ty.Iterator[Range]:
    range_text = _strip_codes(line)[range.start : range.start + range.length]
    for name_match in _NAME_PATTERN.finditer(range_text):
        if name is None or name_match.group(0) == name:
            yield Range(
                start=range.start + name_match.start(),
                length=len(name_match.group(0)),
                detail=range.detail,
            )


def _arg_lvar_ranges(
    line: str, arg_names: ty.Collection[str]
) -> ty.Iterator[Range]:
    for name_match in _NAME_PATTERN.finditer(_strip_codes(line)):
        name = name_match.group(0)
        if name in arg_names:
            yield Range(
                start=name_match.start(),
                length=len(name),
                detail=RangeDetail(LVarDetail(name=name, is_arg=True)),
            )


_ADDRESS_CODE = chr(ida_lines.COLOR_ADDR)


@dataclass
class _FuncLines:
    comment: tuple[str, ...]
    signature: tuple[str, ...]
    body: tuple[str, ...]

    @staticmethod
    def from_func_sync(func: _CFunc) -> "_FuncLines":
        ida_tasks.assert_running_in_task()

        def no_address(line: str) -> bool:
            return not any(
                _ADDRESS_CODE in tag_codes for tag_codes, _ in _tags_sync(line)
            )

        def is_comment(line: str) -> bool:
            return _strip_codes(line).startswith("//")

        lines: ty.Iterator[str] = (
            pseudocode_line.line for pseudocode_line in func.get_pseudocode()
        )

        preamble_lines, body_lines = before_and_after(no_address, lines)
        comment_lines, signature_lines = before_and_after(
            is_comment, preamble_lines
        )
        return _FuncLines(
            comment=tuple(comment_lines),
            signature=tuple(signature_lines),
            body=tuple(body_lines),
        )
