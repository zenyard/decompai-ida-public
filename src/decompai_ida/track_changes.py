import anyio
import ida_funcs
from anyio.abc import ObjectReceiveStream

from decompai_ida import ida_events, ida_tasks, inferences
from decompai_ida.env import Env
from decompai_ida.upload_revisions import Revision, UploadRevisions


async def track_changes_task():
    env = Env.get()

    # Note - we're not interested in past events
    async with env.events.subscribe(replay_recorded=False) as event_receiver:
        while True:
            changed_address = await receive_changed_address(event_receiver)
            if changed_address is None:
                break

            await env.state.mark_address_dirty(changed_address)
            await inferences.clear_inferred_name_marks(changed_address)
            await env.revisions.post(
                UploadRevisions(
                    (Revision((changed_address,)),),
                )
            )


async def receive_changed_address(
    event_receiver: ObjectReceiveStream[ida_events.Event],
) -> int | None:
    async for event in event_receiver:
        # We don't want to be cancelled while holding the event, so it won't be
        # forgotten.
        with anyio.CancelScope(shield=True):
            if not isinstance(event, ida_events.AddressRenamed):
                continue

            # Skip non renames
            if event.old_name == event.new_name:
                continue

            # Skip non functions
            func = await ida_tasks.run_read(ida_funcs.get_func, event.address)
            if func is None:
                continue

            # We don't care about thunk renames (IDA performs these automatically)
            if func.flags & ida_funcs.FUNC_THUNK:
                continue

            return event.address
