import * as React from "react";

import { OriginBadge } from "@/components/origin-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, type MergedHost } from "@/lib/api";

// The API's page size for GET /inventories/{id}/hosts.
const PAGE_SIZE = 100;

/**
 * The hosts a run sees, merged from the inventory and its sources, searchable and paged; with
 * `group`, only the hosts in that group and the groups below it. Vars arrive masked.
 */
export function HostList({
  inventoryId,
  version,
  group,
  title,
}: {
  inventoryId: number;
  /** Changes after a refresh, to reload. */
  version: number;
  group?: string;
  title: string;
}) {
  const [query, setQuery] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [result, setResult] = React.useState<{ total: number; hosts: MergedHost[] } | null>(null);

  // A new group starts afresh: first page, and no hosts from the previous group meanwhile.
  // A new search starts at the first page too.
  const [scope, setScope] = React.useState({ query, group });
  if (scope.query !== query || scope.group !== group) {
    if (scope.group !== group) setResult(null);
    setScope({ query, group });
    setPage(1);
  }

  React.useEffect(() => {
    let active = true;
    const timer = window.setTimeout(() => {
      api
        .inventoryHosts(inventoryId, query.trim(), page, group)
        .then((r) => active && setResult(r))
        .catch(() => active && setResult(null));
    }, 200);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
    // oxlint-disable-next-line react/exhaustive-effect-dependencies -- version changes after a refresh, to reload
  }, [inventoryId, query, page, group, version]);

  const first = (page - 1) * PAGE_SIZE + 1;
  const last = result ? first + result.hosts.length - 1 : 0;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="min-w-0 text-sm font-medium wrap-anywhere">
          {title}
          {result ? ` (${result.total})` : ""}
        </span>
        <Input
          aria-label="Search hosts"
          placeholder="Search hosts"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="h-8 max-w-56"
        />
      </div>
      <div className="flex flex-col divide-y divide-border rounded-md border border-border">
        {result?.hosts.map((host) => (
          <details key={host.name} className="group px-3 py-2">
            <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 text-sm">
              <span className="font-mono wrap-anywhere">{host.name}</span>
              <OriginBadge origin={host.origin} />
              {host.groups.map((name) => (
                <Badge key={name} variant="outline">
                  {name}
                </Badge>
              ))}
            </summary>
            <pre className="mt-2 overflow-x-auto rounded bg-muted/40 p-2 text-xs">
              {JSON.stringify(host.vars, null, 2)}
            </pre>
            {host.overridden.length > 0 && (
              <p className="mt-1 text-xs text-muted-foreground">
                The inventory&apos;s own vars replace the source&apos;s: {host.overridden.join(", ")}
              </p>
            )}
          </details>
        ))}
        {result && result.hosts.length === 0 && (
          <p className="px-3 py-2 text-sm text-muted-foreground">No hosts match.</p>
        )}
      </div>
      {result && result.total > PAGE_SIZE && (
        <nav aria-label="Host pages" className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-muted-foreground">
            {first}–{last} of {result.total}
          </span>
          <span className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page === 1} onClick={() => setPage(page - 1)}>
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page * PAGE_SIZE >= result.total}
              onClick={() => setPage(page + 1)}
            >
              Next
            </Button>
          </span>
        </nav>
      )}
    </div>
  );
}
