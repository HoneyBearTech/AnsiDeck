import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/context/auth-context";
import {
  api,
  ApiError,
  type Credential,
  type HostOrigin,
  type InventoryRefresh,
  type InventorySnapshot,
  type InventorySource,
  type InventoryTargets,
  type MergedHost,
} from "@/lib/api";

const INTERVALS: { value: number; label: string }[] = [
  { value: 0, label: "When something changes" },
  { value: 300, label: "Every 5 minutes" },
  { value: 900, label: "Every 15 minutes" },
  { value: 3600, label: "Every hour" },
  { value: 21600, label: "Every 6 hours" },
  { value: 86400, label: "Every day" },
];

const EXAMPLES: { label: string; config: string }[] = [
  {
    label: "constructed",
    config: `plugin: ansible.builtin.constructed
strict: false
# Groups from host vars: os=debian puts a host in os_debian.
keyed_groups:
  - key: os
    prefix: os
groups:
  webservers: "'web' in (role | default(''))"
`,
  },
  {
    label: "NetBox",
    config: `plugin: netbox.netbox.nb_inventory
api_endpoint: https://netbox.example.com
token: "{{ lookup('env', 'NETBOX_TOKEN') }}"
group_by:
  - device_roles
  - sites
`,
  },
  {
    label: "generator",
    config: `plugin: ansible.builtin.generator
hosts:
  name: "{{ app }}-{{ env }}"
layers:
  app: [web, api]
  env: [stage, prod]
`,
  },
];

function errorMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : "Something went wrong";
}

function busy(refresh: InventoryRefresh | null | undefined): boolean {
  return refresh?.status === "queued" || refresh?.status === "running";
}

function when(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "never";
}

export function RefreshBadge({ refresh }: { refresh: InventoryRefresh | null }) {
  if (!refresh) return <Badge variant="outline">not refreshed</Badge>;
  if (refresh.status === "queued") return <Badge variant="outline">queued</Badge>;
  if (refresh.status === "running") return <Badge variant="changed">refreshing</Badge>;
  if (refresh.status === "success") return <Badge variant="ok">refreshed</Badge>;
  return <Badge variant="failed">{refresh.status === "timed_out" ? "timed out" : "failed"}</Badge>;
}

export function OriginBadge({ origin }: { origin: HostOrigin }) {
  if (origin === "static") return <Badge variant="outline">inventory</Badge>;
  if (origin === "source") return <Badge variant="skipped">source</Badge>;
  return (
    <Badge variant="skipped" title="From a source, with some vars set by the inventory itself">
      source + inventory
    </Badge>
  );
}

function SourceDialog({
  inventoryId,
  projectId,
  source,
  open,
  onClose,
  onSaved,
}: {
  inventoryId: number;
  projectId: number;
  source: InventorySource | null;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  // Mounted per dialog opening (keyed by the source), so the fields start from it.
  const [name, setName] = React.useState(source?.name ?? "");
  const [config, setConfig] = React.useState(source?.config ?? EXAMPLES[0]?.config ?? "");
  const [credentialId, setCredentialId] = React.useState<string>(
    source?.credential_id ? String(source.credential_id) : "none",
  );
  const [enabled, setEnabled] = React.useState(source?.enabled ?? true);
  const [credentials, setCredentials] = React.useState<Credential[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    api
      .listCredentials("env")
      .then((list) => setCredentials(list.filter((c) => c.project_id === projectId)))
      .catch(() => setCredentials([]));
  }, [projectId]);

  async function handleSave() {
    setError(null);
    setSaving(true);
    const input = {
      name: name.trim(),
      config,
      credential_id: credentialId === "none" ? null : Number(credentialId),
      enabled,
    };
    try {
      if (source) await api.updateInventorySource(inventoryId, source.id, input);
      else await api.createInventorySource(inventoryId, input);
      onSaved();
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{source ? "Edit source" : "Add source"}</DialogTitle>
          <DialogDescription>
            An inventory plugin&apos;s config. It runs in a worker when the inventory is refreshed, together
            with the inventory&apos;s own hosts; <code>constructed</code> sources run last and can group all
            of them.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="source-name">Name</Label>
            <Input id="source-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Label htmlFor="source-config">Plugin config (YAML)</Label>
              <div className="flex flex-wrap gap-1">
                <span className="text-xs text-muted-foreground">Examples:</span>
                {EXAMPLES.map((example) => (
                  <Button
                    key={example.label}
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 text-xs"
                    onClick={() => setConfig(example.config)}
                  >
                    {example.label}
                  </Button>
                ))}
              </div>
            </div>
            <Textarea
              id="source-config"
              value={config}
              onChange={(e) => setConfig(e.target.value)}
              className="min-h-56 font-mono text-xs"
              spellCheck={false}
            />
            <p className="text-xs text-muted-foreground">
              Anyone who can see this inventory can read the config: put tokens in an environment-variables
              credential and refer to them with <code>{"{{ lookup('env', 'NAME') }}"}</code>.
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <Label>Credential (environment variables)</Label>
            <Select value={credentialId} onValueChange={setCredentialId}>
              <SelectTrigger aria-label="Credential">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None</SelectItem>
                {credentials.map((credential) => (
                  <SelectItem key={credential.id} value={String(credential.id)}>
                    {credential.name}
                    {credential.env_names ? ` (${credential.env_names.join(", ")})` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <Switch id="source-enabled" checked={enabled} onCheckedChange={setEnabled} />
            <Label htmlFor="source-enabled">Enabled</Label>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleSave} disabled={saving || !name.trim() || !config.trim()}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function HostsPreview({ inventoryId, version }: { inventoryId: number; version: number }) {
  const [query, setQuery] = React.useState("");
  const [result, setResult] = React.useState<{ total: number; hosts: MergedHost[] } | null>(null);

  React.useEffect(() => {
    let active = true;
    const timer = window.setTimeout(() => {
      api
        .inventoryHosts(inventoryId, query.trim())
        .then((r) => active && setResult(r))
        .catch(() => active && setResult(null));
    }, 200);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
    // oxlint-disable-next-line react/exhaustive-effect-dependencies -- version changes after a refresh, to reload
  }, [inventoryId, query, version]);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium">Hosts a run sees{result ? ` (${result.total})` : ""}</span>
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
              <span className="font-mono">{host.name}</span>
              <OriginBadge origin={host.origin} />
              {host.groups.map((group) => (
                <Badge key={group} variant="outline">
                  {group}
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
        {result && result.total > result.hosts.length && (
          <p className="px-3 py-2 text-xs text-muted-foreground">
            Showing {result.hosts.length} of {result.total}: search to narrow down.
          </p>
        )}
      </div>
    </div>
  );
}

/** An inventory's dynamic sources, their refreshes and what they found. Polls while a refresh
 * is queued or running. */
export function InventorySourcesPanel({
  inventoryId,
  projectId,
  onRefreshed,
}: {
  inventoryId: number;
  projectId: number;
  onRefreshed?: () => void;
}) {
  const { canInProject } = useAuth();
  const canManage = canInProject(projectId, "sources:manage");
  const canRefresh = canInProject(projectId, "content:write");
  const [sources, setSources] = React.useState<InventorySource[]>([]);
  const [targets, setTargets] = React.useState<InventoryTargets | null>(null);
  const [snapshot, setSnapshot] = React.useState<InventorySnapshot | null>(null);
  // Kept apart: a reload after a failed action must not wipe the action's error.
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const error = actionError ?? loadError;
  const [editing, setEditing] = React.useState<InventorySource | "new" | null>(null);
  const [version, setVersion] = React.useState(0);
  const wasBusy = React.useRef(false);

  const load = React.useCallback(() => {
    Promise.all([
      api.listInventorySources(inventoryId),
      api.inventoryTargets(inventoryId),
      api.getInventorySnapshot(inventoryId),
    ])
      .then(([list, t, s]) => {
        setSources(list);
        setTargets(t);
        setSnapshot(s);
        setLoadError(null);
        const now = busy(t.last_refresh);
        if (wasBusy.current && !now) {
          setVersion((v) => v + 1);
          onRefreshed?.();
        }
        wasBusy.current = now;
      })
      .catch((err) => setLoadError(errorMessage(err)));
  }, [inventoryId, onRefreshed]);

  React.useEffect(() => {
    load();
  }, [load]);

  const refreshing = busy(targets?.last_refresh);
  React.useEffect(() => {
    if (!refreshing) return;
    const timer = window.setInterval(load, 2000);
    return () => window.clearInterval(timer);
  }, [refreshing, load]);

  async function act(action: () => Promise<unknown>) {
    setActionError(null);
    try {
      await action();
    } catch (err) {
      setActionError(errorMessage(err));
    }
    load();
  }

  if (!canManage && sources.length === 0 && !error) return null;
  const last = targets?.last_refresh ?? null;

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
        <div className="flex flex-col gap-1">
          <CardTitle>Dynamic sources</CardTitle>
          <p className="text-sm text-muted-foreground">
            Hosts and groups from inventory plugins, refreshed in a worker and kept as a snapshot. Runs use
            the snapshot current when they start; the inventory&apos;s own host vars win.
          </p>
        </div>
        <div className="flex gap-2">
          {canRefresh && sources.some((s) => s.enabled) && (
            <Button
              size="sm"
              variant="outline"
              disabled={refreshing}
              onClick={() => act(() => api.refreshInventory(inventoryId))}
            >
              {refreshing ? "Refreshing…" : "Refresh now"}
            </Button>
          )}
          {canManage && (
            <Button size="sm" variant="outline" onClick={() => setEditing("new")}>
              Add source
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {error && <p className="text-sm text-destructive">{error}</p>}
        {sources.length > 0 && (
          <div className="flex flex-col gap-2 rounded-md border border-border p-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <RefreshBadge refresh={last} />
              {last && (
                <span className="text-muted-foreground">
                  {when(last.finished_at ?? last.queued_at)} · {last.trigger.replace("_", " ")}
                  {last.requested_by ? ` by ${last.requested_by}` : ""}
                </span>
              )}
              {targets?.snapshot_at && (
                <span className="text-muted-foreground">
                  · snapshot of {when(targets.snapshot_at)}: {snapshot?.host_count ?? "?"} hosts,{" "}
                  {snapshot?.group_count ?? "?"} groups
                </span>
              )}
            </div>
            {last?.error && last.status !== "success" && (
              <pre className="whitespace-pre-wrap text-xs text-destructive">{last.error}</pre>
            )}
            {last && last.status !== "success" && !refreshing && targets?.snapshot_id && (
              <p className="text-xs text-muted-foreground">Runs keep using the last good snapshot.</p>
            )}
            {canManage ? (
              <div className="flex flex-wrap items-center gap-2">
                <Label className="text-xs text-muted-foreground">Refresh</Label>
                <Select
                  value={String(targets?.refresh_interval_seconds ?? 0)}
                  onValueChange={(value) =>
                    act(() => api.setInventoryRefreshInterval(inventoryId, Number(value)))
                  }
                >
                  <SelectTrigger className="h-8 w-56" aria-label="Refresh interval">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {INTERVALS.map((interval) => (
                      <SelectItem key={interval.value} value={String(interval.value)}>
                        {interval.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            ) : null}
          </div>
        )}
        {sources.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No sources yet. Add a plugin config (NetBox, a cloud, or <code>constructed</code> to group the
            hosts below by their vars).
          </p>
        )}
        {sources.map((source) => (
          <div
            key={source.id}
            className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border p-3"
          >
            <div className="flex flex-col gap-1">
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{source.name}</span>
                <span className="font-mono text-xs text-muted-foreground">{source.plugin}</span>
                {!source.enabled && <Badge variant="outline">off</Badge>}
              </span>
              {source.credential_name && (
                <span className="text-xs text-muted-foreground">credential: {source.credential_name}</span>
              )}
            </div>
            {canManage && (
              <div className="flex items-center gap-2">
                <Switch
                  aria-label={`${source.name} enabled`}
                  checked={source.enabled}
                  onCheckedChange={(enabled) =>
                    act(() => api.updateInventorySource(inventoryId, source.id, { enabled }))
                  }
                />
                <Button size="sm" variant="outline" onClick={() => setEditing(source)}>
                  Edit
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => act(() => api.deleteInventorySource(inventoryId, source.id))}
                >
                  Delete
                </Button>
              </div>
            )}
          </div>
        ))}
        {snapshot && (
          <>
            {snapshot.warnings.length > 0 && (
              <div className="rounded-md bg-status-changed/10 p-3">
                <p className="text-sm font-medium text-status-changed">Warnings from the last refresh</p>
                <ul className="list-disc pl-5 text-xs text-status-changed">
                  {snapshot.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </div>
            )}
            {snapshot.groups.length > 0 && (
              <div className="flex flex-col gap-2">
                <span className="text-sm font-medium">Groups from sources</span>
                <div className="flex flex-wrap gap-2">
                  {snapshot.groups.map((group) => (
                    <Badge key={group.name} variant="outline" title={group.children.join(", ")}>
                      {group.name} · {group.hosts}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            <HostsPreview inventoryId={inventoryId} version={version} />
          </>
        )}
      </CardContent>
      {editing !== null && (
        <SourceDialog
          key={editing === "new" ? "new" : editing.id}
          inventoryId={inventoryId}
          projectId={projectId}
          source={editing === "new" ? null : editing}
          open
          onClose={() => setEditing(null)}
          onSaved={load}
        />
      )}
    </Card>
  );
}
