import graphlib
import typing as ty

import ida_funcs
import idautils
import typing_extensions as tye
from anyio import from_thread, to_thread
from more_itertools import side_effect

from decompai_ida import ida_tasks

_AddressGraph: tye.TypeAlias = ty.Mapping[int, ty.Collection[int]]


async def get_funcs_in_approx_topo_order(
    func_addresses: ty.Iterable[int],
) -> ty.Sequence[int]:
    """
    Returns given functions in approximate topological order.

    Each given address must be that starting address of a function.
    """

    func_to_calls = {func_address: set() for func_address in func_addresses}

    async for caller, callee in _read_calls(func_to_calls):
        if caller in func_to_calls:
            func_to_calls[caller].add(callee)

    return await _approx_topo_order(func_to_calls)


@ida_tasks.wrap_generator
def _read_calls(
    target_addresses: ty.Iterable[int],
) -> ty.Iterator[tuple[int, int]]:
    for target_address in target_addresses:
        for code_ref in idautils.CodeRefsTo(target_address, flow=False):
            from_func = ida_funcs.get_func(code_ref)
            if from_func is not None:
                yield (from_func.start_ea, target_address)


async def _approx_topo_order(graph: _AddressGraph) -> ty.Sequence[int]:
    """
    Returns an approximate topological ordering of nodes in graph, given
    by mapping between node to its dependencies (predecessors).

    If cycles exist in graph, arbitrary edges would be ignored.
    """

    def _compute_approx_topo_order(graph: _AddressGraph):
        g = {node: set(deps) for node, deps in graph.items()}

        while True:
            try:
                return list(
                    side_effect(
                        lambda _: from_thread.check_cancelled(),
                        graphlib.TopologicalSorter(g).static_order(),
                    )
                )
            except graphlib.CycleError as e:
                cycle = e.args[1]
                dep = cycle[0]
                node = cycle[1]
                assert dep in g[node]
                g[node].remove(dep)

    # This may be compute heavy, move to worker thread.
    return await to_thread.run_sync(_compute_approx_topo_order, graph)
