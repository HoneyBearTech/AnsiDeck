import * as React from "react";
import { Link, useParams } from "react-router-dom";

import { PageHeader } from "@/components/page-header";
import { InventorySourcesPanel } from "@/components/inventory-sources-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { Textarea } from "@/components/ui/textarea";
import { api, ApiError, type InventoryDetail, type InventoryHost } from "@/lib/api";
import { useConfirmedAction } from "@/lib/use-confirmed-action";

function GroupDialog({ inventoryId, onCreated }: { inventoryId: number; onCreated: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  async function handleCreate() {
    setError(null);
    try {
      await api.createGroup(inventoryId, name);
      setName("");
      setOpen(false);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">Add group</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New group</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-2">
          <Label htmlFor="group-name">Name</Label>
          <Input id="group-name" value={name} onChange={(e) => setName(e.target.value)} />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleCreate} disabled={!name}>
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function HostDialog({
  inventoryId,
  groups,
  host,
  onSaved,
}: {
  inventoryId: number;
  groups: InventoryDetail["groups"];
  host?: InventoryHost;
  onSaved: () => void;
}) {
  const [open, setOpen] = React.useState(false);
  const [hostname, setHostname] = React.useState(host?.hostname ?? "");
  const [varsText, setVarsText] = React.useState(host ? JSON.stringify(host.vars, null, 2) : "{}");
  const [groupIds, setGroupIds] = React.useState<Set<number>>(new Set(host?.group_ids ?? []));
  const [error, setError] = React.useState<string | null>(null);

  function toggleGroup(groupId: number) {
    setGroupIds((prev) => {
      const next = new Set(prev);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return next;
    });
  }

  async function handleSave() {
    setError(null);
    let vars: Record<string, unknown>;
    try {
      vars = JSON.parse(varsText);
    } catch {
      setError("Vars must be valid JSON");
      return;
    }

    try {
      const payload = { hostname, vars, group_ids: Array.from(groupIds) };
      if (host) {
        await api.updateHost(inventoryId, host.id, payload);
      } else {
        await api.createHost(inventoryId, payload);
      }
      setOpen(false);
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant={host ? "outline" : "default"}>
          {host ? "Edit" : "Add host"}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{host ? "Edit host" : "New host"}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="host-hostname">Hostname</Label>
            <Input id="host-hostname" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="host-vars">Vars (JSON)</Label>
            <Textarea
              id="host-vars"
              value={varsText}
              onChange={(e) => setVarsText(e.target.value)}
              className="min-h-24 font-mono"
              spellCheck={false}
            />
          </div>
          {groups.length > 0 && (
            <div className="flex flex-col gap-2">
              <Label>Groups</Label>
              <div className="flex flex-col gap-2">
                {groups.map((group) => (
                  <label key={group.id} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={groupIds.has(group.id)}
                      onCheckedChange={() => toggleGroup(group.id)}
                    />
                    {group.name}
                  </label>
                ))}
              </div>
            </div>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleSave} disabled={!hostname}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function InventoryDetailPage() {
  const params = useParams<{ id: string }>();
  const inventoryId = Number(params.id);
  const [inventory, setInventory] = React.useState<InventoryDetail | null>(null);
  const { can } = useAuth();
  const canWrite = can("content:write");

  const refresh = React.useCallback(() => {
    api.getInventory(inventoryId).then(setInventory);
  }, [inventoryId]);
  const deletion = useConfirmedAction(refresh);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  if (!inventory) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }

  function groupName(groupId: number): string {
    return inventory?.groups.find((g) => g.id === groupId)?.name ?? "?";
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={inventory.name}
        description={inventory.description}
        back={{ to: "/inventories", label: "Inventories" }}
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to={`/inventories/${inventoryId}/graph`}>Group graph</Link>
          </Button>
        }
      />

      {deletion.error && <p className="text-sm text-destructive">{deletion.error}</p>}

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <CardTitle>Groups</CardTitle>
          {canWrite && <GroupDialog inventoryId={inventoryId} onCreated={refresh} />}
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {inventory.groups.length === 0 && <p className="text-sm text-muted-foreground">No groups yet.</p>}
          {inventory.groups.map((group) => (
            <div key={group.id} className="flex flex-wrap items-center justify-between gap-2">
              <span className="min-w-0 text-sm wrap-anywhere">
                {group.name}{" "}
                <span className="text-muted-foreground">
                  ({inventory.hosts.filter((h) => h.group_ids.includes(group.id)).length} hosts)
                </span>
              </span>
              {canWrite && (
                <Button variant="destructive-outline" size="sm" onClick={() =>
                    deletion.run(`Delete the group "${group.name}"? Its hosts stay in the inventory.`, () =>
                      api.deleteGroup(inventoryId, group.id),
                    )
                  }>
                  Delete
                </Button>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <CardTitle>Hosts</CardTitle>
          {canWrite && <HostDialog inventoryId={inventoryId} groups={inventory.groups} onSaved={refresh} />}
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {inventory.hosts.length === 0 && <p className="text-sm text-muted-foreground">No hosts yet.</p>}
          {inventory.hosts.map((host) => (
            <div key={host.id} className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 flex-col gap-1">
                <span className="text-sm font-medium wrap-anywhere">{host.hostname}</span>
                <div className="flex flex-wrap gap-1">
                  {host.group_ids.map((groupId) => (
                    <Badge key={groupId} variant="outline">
                      {groupName(groupId)}
                    </Badge>
                  ))}
                </div>
              </div>
              {canWrite && (
                <div className="flex gap-2">
                  <HostDialog
                    inventoryId={inventoryId}
                    groups={inventory.groups}
                    host={host}
                    onSaved={refresh}
                  />
                  <Button variant="destructive-outline" size="sm" onClick={() =>
                      deletion.run(`Delete the host "${host.hostname}" and its vars?`, () =>
                        api.deleteHost(inventoryId, host.id),
                      )
                    }>
                    Delete
                  </Button>
                </div>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      <InventorySourcesPanel inventoryId={inventoryId} projectId={inventory.project_id} />
    </div>
  );
}
