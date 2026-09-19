import * as React from "react";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, type AuditEvent } from "@/lib/api";

const PAGE_SIZE = 25;
const ANY = "__any__";

const OUTCOME_VARIANT: Record<AuditEvent["outcome"], BadgeProps["variant"]> = {
  success: "ok",
  failure: "failed",
  denied: "changed",
};

function describeTarget(event: AuditEvent): string | null {
  if (!event.target_type && !event.target_name) return null;
  const name = event.target_name ? ` "${event.target_name}"` : "";
  const id = event.target_id !== null ? ` #${event.target_id}` : "";
  return `${event.target_type ?? "target"}${id}${name}`;
}

export function AuditPage() {
  const [items, setItems] = React.useState<AuditEvent[]>([]);
  const [total, setTotal] = React.useState(0);
  const [offset, setOffset] = React.useState(0);
  const [action, setAction] = React.useState("");
  const [actor, setActor] = React.useState("");
  const [outcome, setOutcome] = React.useState(ANY);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .listAudit({
        limit: PAGE_SIZE,
        offset,
        action: action.trim() || undefined,
        actor: actor.trim() || undefined,
        outcome: outcome === ANY ? undefined : outcome,
      })
      .then((page) => {
        setItems(page.items);
        setTotal(page.total);
        setError(null);
      })
      .catch(() => setError("Could not load the audit log"))
      .finally(() => setLoading(false));
  }, [offset, action, actor, outcome]);

  React.useEffect(() => {
    load();
  }, [load]);

  function resetOffset<T>(setter: (value: T) => void) {
    return (value: T) => {
      setOffset(0);
      setter(value);
    };
  }

  const lastPage = Math.max(0, Math.ceil(total / PAGE_SIZE) - 1);
  const page = Math.floor(offset / PAGE_SIZE);

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">Audit log</h1>

      <div className="flex flex-wrap items-end gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor="audit-action">Action starts with</Label>
          <Input
            id="audit-action"
            placeholder="e.g. user. or auth.login"
            value={action}
            onChange={(e) => resetOffset(setAction)(e.target.value)}
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor="audit-actor">Actor</Label>
          <Input
            id="audit-actor"
            placeholder="username"
            value={actor}
            onChange={(e) => resetOffset(setActor)(e.target.value)}
          />
        </div>
        <div className="flex flex-col gap-2">
          <Label>Outcome</Label>
          <Select value={outcome} onValueChange={resetOffset(setOutcome)}>
            <SelectTrigger className="w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ANY}>Any</SelectItem>
              <SelectItem value="success">success</SelectItem>
              <SelectItem value="failure">failure</SelectItem>
              <SelectItem value="denied">denied</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button variant="outline" onClick={load}>
          Refresh
        </Button>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {!loading && items.length === 0 && <p className="text-sm text-muted-foreground">No matching events.</p>}

      <div className="flex flex-col gap-2">
        {items.map((event) => {
          const target = describeTarget(event);
          return (
            <Card key={event.id}>
              <CardContent className="flex flex-col gap-1 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Badge variant={OUTCOME_VARIANT[event.outcome]}>{event.outcome}</Badge>
                    <span className="font-mono text-sm">{event.action}</span>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {new Date(event.created_at).toLocaleString()}
                  </span>
                </div>
                <p className="text-sm text-muted-foreground">
                  {event.actor_username ?? "system"}
                  {target && ` → ${target}`}
                  {event.ip && ` · ${event.ip}`}
                </p>
                {event.detail && Object.keys(event.detail).length > 0 && (
                  <p className="font-mono text-xs text-muted-foreground">{JSON.stringify(event.detail)}</p>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          {total} event{total === 1 ? "" : "s"} · page {page + 1} of {lastPage + 1}
        </span>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= lastPage}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}
