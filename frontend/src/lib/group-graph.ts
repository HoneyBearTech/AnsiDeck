import type { InventoryGraph } from "@/lib/api";

export const GROUP_BOTH_TITLE = "Defined by the inventory and by a source";

/** Parent and child lookups for an inventory's group graph. */
export function indexGroups(graph: InventoryGraph) {
  const byName = new Map(graph.groups.map((g) => [g.name, g]));
  const parents = new Map<string, string[]>();
  for (const group of graph.groups) {
    for (const child of group.children) {
      parents.set(child, [...(parents.get(child) ?? []), group.name]);
    }
  }
  const roots = graph.groups.filter((g) => !parents.has(g.name)).map((g) => g.name);
  const childrenOf = (name: string | null) => (name === null ? roots : (byName.get(name)?.children ?? []));
  return { byName, parents, roots, childrenOf };
}

export type GroupIndex = ReturnType<typeof indexGroups>;
