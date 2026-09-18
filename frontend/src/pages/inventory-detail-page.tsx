import * as React from "react";
import { useParams } from "react-router-dom";

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
import { Textarea } from "@/components/ui/textarea";
import { api, ApiError, type InventoryDetail, type InventoryHost } from "@/lib/api";

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
        <Button size="sm">Add Group</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Group</DialogTitle>
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
  const [varsText, setVarsText] = React.useState(
    host ? JSON.stringify(host.vars, null, 2) : "{}",
  );
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
          {host ? "Edit" : "Add Host"}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{host ? "Edit Host" : "New Host"}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="host-hostname">Hostname</Label>
            <Input
              id="host-hostname"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
            />
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

  const refresh = React.useCallback(() => {
    api.getInventory(inventoryId).then(setInventory);
  }, [inventoryId]);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  if (!inventory) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }

  async function handleDeleteGroup(groupId: number) {
    await api.deleteGroup(inventoryId, groupId);
    refresh();
  }

  async function handleDeleteHost(hostId: number) {
    await api.deleteHost(inventoryId, hostId);
    refresh();
  }

  function groupName(groupId: number): string {
    return inventory?.groups.find((g) => g.id === groupId)?.name ?? "?";
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">{inventory.name}</h1>
        {inventory.description && (
          <p className="text-sm text-muted-foreground">{inventory.description}</p>
        )}
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Groups</CardTitle>
          <GroupDialog inventoryId={inventoryId} onCreated={refresh} />
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {inventory.groups.length === 0 && (
            <p className="text-sm text-muted-foreground">No groups yet.</p>
          )}
          {inventory.groups.map((group) => (
            <div key={group.id} className="flex items-center justify-between">
              <span className="text-sm">{group.name}</span>
              <Button variant="outline" size="sm" onClick={() => handleDeleteGroup(group.id)}>
                Delete
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Hosts</CardTitle>
          <HostDialog inventoryId={inventoryId} groups={inventory.groups} onSaved={refresh} />
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {inventory.hosts.length === 0 && (
            <p className="text-sm text-muted-foreground">No hosts yet.</p>
          )}
          {inventory.hosts.map((host) => (
            <div key={host.id} className="flex items-center justify-between">
              <div className="flex flex-col gap-1">
                <span className="text-sm font-medium">{host.hostname}</span>
                <div className="flex gap-1">
                  {host.group_ids.map((groupId) => (
                    <Badge key={groupId} variant="outline">
                      {groupName(groupId)}
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="flex gap-2">
                <HostDialog
                  inventoryId={inventoryId}
                  groups={inventory.groups}
                  host={host}
                  onSaved={refresh}
                />
                <Button variant="outline" size="sm" onClick={() => handleDeleteHost(host.id)}>
                  Delete
                </Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
