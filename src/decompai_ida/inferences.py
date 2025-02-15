import typing as ty
from collections import defaultdict
from contextlib import contextmanager

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name
import idc
import structlog
import typing_extensions as tye
from anyio import TASK_STATUS_IGNORED
from anyio.abc import TaskStatus

from decompai_client import (
    FunctionOverview,
    Inference,
    Name,
    ParametersMapping,
    VariablesMapping,
)
from decompai_ida import api, ida_tasks, logger, markdown, objects, state
from decompai_ida.env import Env
from decompai_ida.lvars import (
    apply_parameter_renames,
    apply_variable_renames,
    get_parameter_names,
    get_variable_names,
)


def _rgb_to_int(r: int, g: int, b: int) -> int:
    return (b << 16) + (g << 8) + r


_INFERRED_COLOR = _rgb_to_int(220, 202, 255)


async def apply_inferences(inferences: ty.Iterable[Inference]):
    by_address = defaultdict[int, list[Inference]](list)
    for inference in inferences:
        if inference.actual_instance is not None:
            by_address[
                api.parse_address(inference.actual_instance.address)
            ].append(inference)

    await ida_tasks.for_each(
        by_address.items(),
        lambda item: _apply_inferences_for_address_sync(*item),
    )


def _apply_inferences_for_address_sync(
    address: int, inferences: ty.Collection[Inference]
):
    ida_tasks.assert_running_in_task()

    with (
        structlog.contextvars.bound_contextvars(address=address),
        _maintain_uploaded_hash_sync(address),
    ):
        logger.get().debug("Applying inferences", count=len(inferences))
        for inference in inferences:
            try:
                inference = _apply_local_transformations(inference)
                assert inference.actual_instance is not None
                assert (
                    api.parse_address(inference.actual_instance.address)
                    == address
                )

                if isinstance(inference.actual_instance, FunctionOverview):
                    _apply_overview_sync(inference.actual_instance)
                elif isinstance(inference.actual_instance, Name):
                    _apply_name_sync(inference.actual_instance)
                elif isinstance(inference.actual_instance, ParametersMapping):
                    _apply_parameters_sync(inference.actual_instance)
                elif isinstance(inference.actual_instance, VariablesMapping):
                    _apply_variables_sync(inference.actual_instance)
                else:
                    _: tye.Never = inference.actual_instance

                state.add_inference_for_address.sync(address, inference)

            except Exception as ex:
                logger.get().warning(
                    "Error while applying inferences", exc_info=ex
                )

    _update_pseudocode_viewer_for_address_sync(address)


def _update_pseudocode_viewer_for_address_sync(address: int):
    ida_tasks.assert_running_in_task()

    current_vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())

    if current_vdui is None:
        return

    if not current_vdui.visible():
        return

    if current_vdui.cfunc is None:
        return

    if current_vdui.cfunc.entry_ea != address:
        return

    current_vdui.refresh_view(True)


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
    ida_tasks.assert_running_in_task()

    func = ida_funcs.get_func(address)
    if func is None or address != func.start_ea:
        return

    if idc.get_color(address, idc.CIC_FUNC) != _INFERRED_COLOR:
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


T = ty.TypeVar("T")


@ida_tasks.wrap
def _get_last_inference_type_sync(
    address: int, inference_type: ty.Type[T]
) -> ty.Union[T, None]:
    ida_tasks.assert_running_in_task()

    inferences = state.get_inferences_for_address.sync(address)
    return next(
        (
            inference.actual_instance
            for inference in reversed(inferences)
            if isinstance(inference.actual_instance, inference_type)
        ),
        None,
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
    ida_tasks.assert_running_in_task()

    address = api.parse_address(overview.address)

    if has_user_defined_comment.sync(address):
        return

    func = ida_funcs.get_func(address)
    assert func is not None

    ida_funcs.set_func_cmt(func, overview.full_description, False)


def _apply_name_sync(name: Name):
    ida_tasks.assert_running_in_task()

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


def _apply_variables_sync(variables_mapping: VariablesMapping):
    ida_tasks.assert_running_in_task()

    address = api.parse_address(variables_mapping.address)
    func = ida_funcs.get_func(address)
    assert func is not None

    failure = ida_hexrays.hexrays_failure_t()
    decompiled = ida_hexrays.decompile_func(
        func,
        failure,
        ida_hexrays.DECOMP_NO_WAIT,
    )
    if decompiled is None:
        raise Exception(f"Can't decompile: {failure.desc()}")

    variable_names = get_variable_names.sync(decompiled)
    # TODO: Not sure if to use last or merge
    last_variables_mapping = _get_last_inference_type_sync.sync(
        address, VariablesMapping
    )
    last_infered_variable_names = set()
    if last_variables_mapping is not None:
        last_infered_variable_names = set(
            last_variables_mapping.variables_mapping.values()
        )
    variable_name_to_variable_name_obj = {
        variable_name.name: variable_name for variable_name in variable_names
    }
    renames = {}
    for original_variable_name in variables_mapping.variables_mapping:
        variable_name = variable_name_to_variable_name_obj.get(
            original_variable_name
        )
        if variable_name is None:
            continue
        if not variable_name.is_dummy:
            if variable_name.name in last_infered_variable_names:
                # Only override user defined variables that were infered
                renames[original_variable_name] = (
                    variables_mapping.variables_mapping[original_variable_name]
                )
        else:
            renames[original_variable_name] = (
                variables_mapping.variables_mapping[original_variable_name]
            )

    apply_variable_renames.sync(decompiled, renames)


def _apply_parameters_sync(parameters_mapping: ParametersMapping):
    ida_tasks.assert_running_in_task()

    address = api.parse_address(parameters_mapping.address)
    parameter_names = get_parameter_names.sync(address)
    # TODO: Not sure if to use last or merge
    last_parameters_mapping = _get_last_inference_type_sync.sync(
        address, ParametersMapping
    )
    last_infered_parameter_names = set()
    if last_parameters_mapping is not None:
        last_infered_parameter_names = set(
            last_parameters_mapping.parameters_mapping.values()
        )

    renames = {}
    for parameter_index, parameter_name in enumerate(parameter_names):
        if (
            not parameter_name.is_dummy
            and parameter_name.name not in last_infered_parameter_names
        ):
            # Skip user defined parameter names
            continue
        new_name = parameters_mapping.parameters_mapping.get(
            parameter_name.name
        )
        if new_name is not None:
            renames[parameter_index] = new_name
    apply_parameter_renames.sync(address, renames)


@contextmanager
def _maintain_uploaded_hash_sync(address: int):
    """
    If object before changes is synced with server (according to hash),
    update the hash once context exists.

    This is for doing changes the we know the server emulates (i.e. applying
    inferences), so the uploaded hash can reflect server's emulated state.
    """
    ida_tasks.assert_running_in_task()

    was_clean = _is_object_known_to_be_clean_sync(address)

    with structlog.contextvars.bound_contextvars(was_clean=was_clean):
        try:
            yield

        finally:
            if was_clean:
                try:
                    updated_hash = objects.hash_object.sync(
                        objects.read_object.sync(address)
                    )
                    status = state.get_sync_status.sync(address)
                    state.set_sync_status.sync(
                        address, status.with_uploaded_hash(updated_hash)
                    )
                    logger.get().debug("Maintained hash")

                except Exception as ex:
                    logger.get().warning(
                        "Error while maintaining hash", exc_info=ex
                    )
                    pass
            else:
                logger.get().debug("Not maintaining hash of dirty object")


def _is_object_known_to_be_clean_sync(address: int) -> bool:
    ida_tasks.assert_running_in_task()

    try:
        status = state.get_sync_status.sync(address)

        # Avoid reading object if possible
        if status.is_handled:
            return True
        if status.uploaded_hash is None:
            return False

        # Finally read object and compare hash
        current_hash = objects.hash_object.sync(
            objects.read_object.sync(address)
        )
        return current_hash == status.uploaded_hash

    except Exception as ex:
        logger.get().warning(
            "Error while checking if object is clean", exc_info=ex
        )
        return False
