import * as React from "react";
import { useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { useAuth } from "@/context/auth-context";
import {
  api,
  ApiError,
  type Credential,
  type InventoryDetail,
  type InventorySummary,
  type PlaybookSummary,
} from "@/lib/api";

const ALL_HOSTS = "__all__";

export function RunTriggerPage() {
  const navigate = useNavigate();
  const { user } = useAuth();

  const [playbooks, setPlaybooks] = React.useState<PlaybookSummary[]>([]);
  const [inventories, setInventories] = React.useState<InventorySummary[]>([]);
  const [credentials, setCredentials] = React.useState<Credential[]>([]);
  const [selectedInventory, setSelectedInventory] = React.useState<InventoryDetail | null>(null);

  const [playbookId, setPlaybookId] = React.useState<string>("");
  const [inventoryId, setInventoryId] = React.useState<string>("");
  const [groupId, setGroupId] = React.useState<string>(ALL_HOSTS);
  const [credentialId, setCredentialId] = React.useState<string>("");
  const [become, setBecome] = React.useState(false);
  const [becomeConfirmed, setBecomeConfirmed] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  React.useEffect(() => {
    api.listPlaybooks().then(setPlaybooks);
    api.listInventories().then(setInventories);
    api.listCredentials().then(setCredentials);
  }, []);

  React.useEffect(() => {
    if (!inventoryId) {
      setSelectedInventory(null);
      return;
    }
    setGroupId(ALL_HOSTS);
    api.getInventory(Number(inventoryId)).then(setSelectedInventory);
  }, [inventoryId]);

  const canSubmit =
    playbookId !== "" &&
    inventoryId !== "" &&
    credentialId !== "" &&
    (!become || becomeConfirmed);

  async function handleSubmit() {
    setError(null);
    setSubmitting(true);
    try {
      const run = await api.createRun({
        playbook_id: Number(playbookId),
        inventory_id: Number(inventoryId),
        group_id: groupId === ALL_HOSTS ? null : Number(groupId),
        credential_id: Number(credentialId),
        become,
      });
      navigate(`/runs/${run.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">New Run</h1>

      <div className="flex flex-col gap-2">
        <Label>Playbook</Label>
        <Select value={playbookId} onValueChange={setPlaybookId}>
          <SelectTrigger>
            <SelectValue placeholder="Select a playbook" />
          </SelectTrigger>
          <SelectContent>
            {playbooks.map((playbook) => (
              <SelectItem key={playbook.id} value={String(playbook.id)}>
                {playbook.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex flex-col gap-2">
        <Label>Inventory</Label>
        <Select value={inventoryId} onValueChange={setInventoryId}>
          <SelectTrigger>
            <SelectValue placeholder="Select an inventory" />
          </SelectTrigger>
          <SelectContent>
            {inventories.map((inventory) => (
              <SelectItem key={inventory.id} value={String(inventory.id)}>
                {inventory.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {selectedInventory && (
        <div className="flex flex-col gap-2">
          <Label>Target</Label>
          <Select value={groupId} onValueChange={setGroupId}>
            <SelectTrigger>
              <SelectValue placeholder="All hosts" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_HOSTS}>All hosts ({selectedInventory.hosts.length})</SelectItem>
              {selectedInventory.groups.map((group) => (
                <SelectItem key={group.id} value={String(group.id)}>
                  Group: {group.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      <div className="flex flex-col gap-2">
        <Label>Credential</Label>
        <Select value={credentialId} onValueChange={setCredentialId}>
          <SelectTrigger>
            <SelectValue placeholder="Select a credential" />
          </SelectTrigger>
          <SelectContent>
            {credentials.map((credential) => (
              <SelectItem key={credential.id} value={String(credential.id)}>
                {credential.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex flex-col gap-3 rounded-md border border-border p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">Run as admin (become root)</p>
            <p className="text-xs text-muted-foreground">Escalates privileges on the target host(s).</p>
          </div>
          <Switch
            checked={become}
            onCheckedChange={(checked) => {
              setBecome(checked);
              if (!checked) setBecomeConfirmed(false);
            }}
          />
        </div>

        {become && (
          <div className="flex flex-col gap-2 rounded-md bg-destructive/10 p-3">
            <p className="text-sm text-destructive">
              This run will execute with root privileges on the target host(s). Triggered as{" "}
              <span className="font-medium">{user?.username}</span>.
            </p>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={becomeConfirmed}
                onCheckedChange={(checked) => setBecomeConfirmed(checked === true)}
              />
              I understand this grants root and want to proceed.
            </label>
          </div>
        )}
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <div>
        <Button onClick={handleSubmit} disabled={!canSubmit || submitting}>
          {submitting ? "Starting…" : "Trigger Run"}
        </Button>
      </div>
    </div>
  );
}
