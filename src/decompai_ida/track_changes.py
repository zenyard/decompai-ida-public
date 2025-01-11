import math
import typing as ty

import anyio
import ida_auto
import ida_funcs
import ida_segment
import idautils

from decompai_ida import ida_events, ida_tasks, objects, state, status
from decompai_ida.async_utils import collect, wait_for_object_of_type
from decompai_ida.env import Env
from decompai_ida.upload_revisions import CheckAddressesForChanges


async def track_changes_task():
    env = Env.get()

    await _wait_for_auto_analysis()

    # Buffer events while scanning database.
    async with env.events.subscribe(buffer_size=math.inf) as event_receiver:
        # Initially check all functions
        async with status.begin_task("local_work"):
            all_funcs = await collect(_all_funcs())

            if len(all_funcs) > 0:
                await env.check_addresses.post(
                    CheckAddressesForChanges(addresses=tuple(all_funcs))
                )

        # Continue tracking change events.
        async for event in event_receiver:
            changed_addresses = (
                await _extract_and_mark_changed_object_addresses(event)
            )

            if len(changed_addresses) > 0:
                await env.check_addresses.post(
                    CheckAddressesForChanges(addresses=changed_addresses)
                )


@ida_tasks.wrap
def _extract_and_mark_changed_object_addresses(
    event: ida_events.Event,
) -> tuple[int, ...]:
    changed_addresses = set(_extract_changed_object_addresses_sync(event))

    for changed_address in changed_addresses:
        state.set_sync_status.sync(
            changed_address,
            state.get_sync_status.sync(
                changed_address
            ).with_incremented_db_revision(),
        )

    return tuple(changed_addresses)


def _extract_changed_object_addresses_sync(
    event: ida_events.Event,
) -> ty.Iterator[int]:
    if not isinstance(event, ida_events.AddressModified):
        return

    object_address = _get_object_address_sync(event.address)
    if object_address is not None:
        yield object_address

    else:
        # Any referencing object may have changed.
        for referencing_address in (
            *idautils.DataRefsTo(event.address),
            *idautils.CodeRefsTo(event.address, flow=False),
        ):
            referencing_address = _get_object_address_sync(referencing_address)
            if referencing_address is not None:
                yield referencing_address


def _get_object_address_sync(address: int) -> ty.Optional[int]:
    # Skip ignored segments
    if objects.is_in_ignored_segment.sync(address):
        return None

    # Skip non functions
    func = ida_funcs.get_func(address)
    if func is None:
        return None

    # Object address is function entry point.
    return func.start_ea


@ida_tasks.wrap_generator
def _all_funcs() -> ty.Iterator[int]:
    for segment_base in idautils.Segments():
        if objects.is_in_ignored_segment.sync(segment_base):
            continue

        segment = ida_segment.getseg(segment_base)
        segment_end = segment_base + segment.size()  # type: ignore
        yield from idautils.Functions(segment_base, segment_end)


async def _wait_for_auto_analysis():
    async with (
        Env.get().events.subscribe() as event_receiver,
        status.begin_task("waiting_for_ida"),
    ):
        while not await ida_tasks.run(ida_auto.auto_is_ok):
            with anyio.move_on_after(1):
                await wait_for_object_of_type(
                    event_receiver,
                    ida_events.InitialAutoAnalysisComplete,
                )
