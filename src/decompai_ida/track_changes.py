import math
import typing as ty

import anyio
import ida_funcs
from anyio.abc import ObjectReceiveStream, ObjectSendStream

from decompai_ida import ida_events, ida_tasks, inferences
from decompai_ida.env import Env
from decompai_ida.upload_revisions import Revision, UploadRevisions


async def track_changes_task(buffer_changes_period: float):
    env = Env.get()

    # Unabounded stream to buffer changes while initial analysis in progress.
    sender, receiver = anyio.create_memory_object_stream(math.inf)

    async with anyio.create_task_group() as tg:
        tg.start_soon(_mark_dirty_and_queue_changes, sender)

        # Start uploading only once initial analysis completes.
        await env.initial_analysis_complete.wait()

        tg.start_soon(
            _buffer_and_upload_dirty_addresses, receiver, buffer_changes_period
        )


async def _mark_dirty_and_queue_changes(output: ObjectSendStream[int]):
    env = Env.get()

    async with env.events.subscribe() as event_receiver:
        async for event in event_receiver:
            changed_address = await _extract_changed_address(event)
            if changed_address is None:
                break

            await env.state.mark_address_dirty(changed_address)
            await inferences.clear_inferred_name_marks(changed_address)
            await output.send(changed_address)


async def _buffer_and_upload_dirty_addresses(
    input: ObjectReceiveStream[int], buffer_changes_period: float
):
    env = Env.get()

    async with input:
        async for address in input:
            addresses = {address}
            with anyio.move_on_after(buffer_changes_period):
                async for address in input:
                    addresses.add(address)

            addresses = [
                address
                async for address in env.state.filter_clean_addresses(addresses)
            ]

            if len(addresses) > 0:
                await env.revisions.post(
                    UploadRevisions((Revision(tuple(addresses)),))
                )


async def _extract_changed_address(event: ida_events.Event) -> ty.Optional[int]:
    if not isinstance(event, ida_events.AddressRenamed):
        return

    # Skip non renames
    if event.old_name == event.new_name:
        return

    # Skip non functions
    func = await ida_tasks.run_read(ida_funcs.get_func, event.address)
    if func is None:
        return

    # We don't care about thunk renames (IDA performs these automatically)
    if func.flags & ida_funcs.FUNC_THUNK:
        return

    return event.address
