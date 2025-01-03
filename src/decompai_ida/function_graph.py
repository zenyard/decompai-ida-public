import graphlib
import typing as ty

import ida_funcs
import ida_segment
import idautils
import typing_extensions as tye
from anyio import from_thread, to_thread
from more_itertools import side_effect

from decompai_ida import ida_tasks

_AddressGraph: tye.TypeAlias = ty.Mapping[int, ty.Collection[int]]

_IGNORED_SEGMENTS = {
    "extern",
    ".plt",
    ".plt.got",
    ".got",
    # TODO: PE, Mach-O segments?
}


class FunctionGraph:
    _approx_topo_order: ty.Sequence[int]

    def __init__(
        self,
        *,
        approx_topo_order: ty.Sequence[int],
    ):
        self._approx_topo_order = approx_topo_order

    def __len__(self) -> int:
        return len(self._approx_topo_order)

    def approx_topo_order(self) -> ty.Iterator[int]:
        """
        Return list of functions in approximate topological order, with nodes of
        call graph appearing before their parents, as long as its acyclic.
        """
        return iter(self._approx_topo_order)

    @staticmethod
    async def build_from_ida() -> "FunctionGraph":
        func_to_callers = dict[int, set[int]]()

        async for func, caller in _read_funcs_to_callers():
            if caller is None:
                func_to_callers[func] = set()
            else:
                func_to_callers[func].add(caller)

        func_to_calls = {func: set() for func in func_to_callers}
        for func, callers in func_to_callers.items():
            for caller in callers:
                if caller in func_to_callers:
                    func_to_calls[caller].add(func)

        approx_topo_order = await _approx_topo_order(func_to_calls)

        return FunctionGraph(
            approx_topo_order=approx_topo_order,
        )


@ida_tasks.read_generator
def _read_funcs_to_callers() -> ty.Iterator[tuple[int, ty.Optional[int]]]:
    for segment_base in idautils.Segments():
        segment = ida_segment.getseg(segment_base)

        if ida_segment.get_segm_class(segment) != "CODE":
            continue

        if ida_segment.get_segm_name(segment) in _IGNORED_SEGMENTS:
            continue

        segment_end = segment_base + segment.size()  # type: ignore

        for func in idautils.Functions(segment_base, segment_end):
            yield (func, None)
            for code_ref in idautils.CodeRefsTo(func, flow=False):
                from_func = ida_funcs.get_func(code_ref)
                if from_func is not None:
                    yield (func, from_func.start_ea)


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
