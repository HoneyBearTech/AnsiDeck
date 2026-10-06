import * as React from "react";
import { useParams, useSearchParams } from "react-router-dom";

import { GroupNeighbourhood } from "@/components/group-neighbourhood";
import { GroupTree } from "@/components/group-tree";
import { HostList } from "@/components/host-list";
import { OriginBadge } from "@/components/origin-badge";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api, ApiError, type InventoryGraph } from "@/lib/api";
import { GROUP_BOTH_TITLE, indexGroups } from "@/lib/group-graph";

function plural(count: number, one: string, many = `${one}s`) {
  return `${count} ${count === 1 ? one : many}`;
}

/** How an inventory's groups nest (its own and its sources'), and the hosts in each. */
export function InventoryGraphPage() {
  const params = useParams<{ id: string }>();
  const inventoryId = Number(params.id);
  const [searchParams, setSearchParams] = useSearchParams();
  const selected = searchParams.get("group");
  const [graph, setGraph] = React.useState<InventoryGraph | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const details = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    let active = true;
    // Only the graph: the inventory's own detail carries host vars this page doesn't need.
    api
      .inventoryGraph(inventoryId)
      .then((g) => active && setGraph(g))
      .catch((err) => active && setError(err instanceof ApiError ? err.message : "Something went wrong"));
    return () => {
      active = false;
    };
  }, [inventoryId]);

  const index = React.useMemo(() => (graph ? indexGroups(graph) : null), [graph]);

  function select(name: string) {
    setSearchParams({ group: name });
    // Below the two-column layout the details sit under the tree: bring them into view.
    if (window.matchMedia?.("(max-width: 1023px)").matches) {
      details.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  if (error) return <p className="text-sm text-destructive">{error}</p>;
  if (!graph || !index) return <p className="text-sm text-muted-foreground">Loading…</p>;

  const group = selected ? index.byName.get(selected) : undefined;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Group graph"
        back={{ to: `/inventories/${inventoryId}`, label: graph.name }}
        description={
          <>
            {plural(graph.groups.length, "group")} and {plural(graph.hosts, "host")}
            {graph.ungrouped > 0 && `, ${graph.ungrouped} of them in no group`}. Counts are a group&apos;s own
            hosts; picking a group lists the hosts in it and the groups below it.
            {graph.snapshot_at && ` Sources as of ${new Date(graph.snapshot_at).toLocaleString()}.`}
          </>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] lg:items-start">
        <Card>
          <CardHeader>
            <CardTitle>Groups</CardTitle>
          </CardHeader>
          <CardContent>
            <GroupTree graph={graph} index={index} selected={selected} onSelect={select} />
          </CardContent>
        </Card>

        <div ref={details} className="flex scroll-mt-4 flex-col gap-6">
          {selected && !group && (
            <p className="text-sm text-destructive">
              This inventory has no group named <span className="font-mono">{selected}</span>.
            </p>
          )}
          {group && (
            <Card>
              <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
                <CardTitle className="min-w-0 font-mono wrap-anywhere">{group.name}</CardTitle>
                <OriginBadge origin={group.origin} bothTitle={GROUP_BOTH_TITLE} />
              </CardHeader>
              <CardContent className="flex flex-col gap-6">
                <GroupNeighbourhood name={group.name} index={index} onSelect={select} />
                <HostList
                  inventoryId={inventoryId}
                  version={0}
                  group={group.name}
                  title={`Hosts in ${group.name} and the groups below it`}
                />
              </CardContent>
            </Card>
          )}
          {!selected && (
            <Card>
              <CardHeader>
                <CardTitle>All hosts</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                <p className="text-sm text-muted-foreground">Pick a group to see where it sits and which hosts it holds.</p>
                <HostList inventoryId={inventoryId} version={0} title="Hosts a run sees" />
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
