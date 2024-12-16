from more_itertools import chunked
import typing as ty

from decompai_ida import ida_tasks, status
from decompai_ida.env import Env
from decompai_ida.function_graph import FunctionGraph
from decompai_ida.upload_revisions import Revision, UploadRevisions


async def perform_initial_analysis(*, objects_per_revision: int):
    env = Env.get()

    async with status.begin_task("Scanning database"):
        func_graph = await FunctionGraph.build_from_ida()

        addresses = [
            address
            async for address in filter_clean_addresses(
                func_graph.approx_topo_order()
            )
        ]

        if len(addresses) == 0:
            return

        revisions = tuple(
            Revision(tuple(addresses))
            for addresses in chunked(addresses, objects_per_revision)
        )

    await env.revisions.post(UploadRevisions(revisions))


@ida_tasks.read_generator
def filter_clean_addresses(addresses: ty.Iterable[int]) -> ty.Iterator[int]:
    env = Env.get()

    return (
        address
        for address in addresses
        if env.state.is_address_dirty_sync(address)
    )
