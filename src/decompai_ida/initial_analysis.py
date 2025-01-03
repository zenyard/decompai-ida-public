from more_itertools import chunked

from decompai_ida import status
from decompai_ida.env import Env
from decompai_ida.function_graph import FunctionGraph
from decompai_ida.upload_revisions import Revision, UploadRevisions


async def perform_initial_analysis(objects_per_revision: int):
    env = Env.get()

    async with status.begin_task("local_work"):
        func_graph = await FunctionGraph.build_from_ida()

        addresses = [
            address
            async for address in env.state.filter_clean_addresses(
                func_graph.approx_topo_order()
            )
        ]

        if len(addresses) == 0:
            return

        revisions = tuple(
            Revision(tuple(addresses))
            for addresses in chunked(addresses, objects_per_revision)
        )

    if len(revisions) > 0:
        await env.revisions.post(UploadRevisions(revisions))
