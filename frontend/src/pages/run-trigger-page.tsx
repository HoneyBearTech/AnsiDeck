import * as React from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { CodeEditor } from "@/components/code-editor";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { useAuth } from "@/context/auth-context";
import {
  api,
  ApiError,
  type Credential,
  type InventoryTargets,
  type InventorySummary,
  type PlaybookSummary,
  type Run,
  type RunRequest,
  type RunTemplate,
  type VaultPassword,
} from "@/lib/api";
import { deletedItems, describeDeleted, hasMaskedValue } from "@/lib/runs";

const ALL_HOSTS = "__all__";
// Targets are group names (a source's groups have no id); prefixed so none can be ALL_HOSTS.
const GROUP_PREFIX = "group:";
const NO_VAULT = "__none__";
// Mirrors the API: 2 h by default, at most 24 h.
const DEFAULT_TIMEOUT_MINUTES = 120;
const MAX_TIMEOUT_MINUTES = 24 * 60;

/** The id of the only item, or "" when there are none or several. */
function only(items: { id: number }[]): string {
  return items.length === 1 ? String(items[0]?.id) : "";
}

/** How fresh a dynamic inventory's hosts are, for the run being set up. */
function SnapshotNote({ targets }: { targets: InventoryTargets }) {
  if (!targets.has_sources) return null;
  if (!targets.snapshot_at) {
    return (
      <p className="text-xs text-destructive">
        This inventory&apos;s dynamic sources haven&apos;t been refreshed yet: refresh it on its page first.
      </p>
    );
  }
  const failed = targets.last_refresh && ["failed", "timed_out"].includes(targets.last_refresh.status);
  return (
    <p className={failed ? "text-xs text-status-changed" : "text-xs text-muted-foreground"}>
      {failed ? "The last refresh failed: " : ""}
      Dynamic hosts as of {new Date(targets.snapshot_at).toLocaleString()}.
    </p>
  );
}

/** Name and description for a new template made of the form's settings. */
function SaveTemplateDialog({
  open,
  onOpenChange,
  onSave,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSave: (name: string, description: string | null) => Promise<string | null>;
}) {
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  async function handleSave() {
    setSaving(true);
    setError(await onSave(name.trim(), description.trim() || null));
    setSaving(false);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Save as template</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            Saves this form&apos;s playbook, inventory, target, credential and options, extra vars included, to
            start again in one step from the Templates page (or by a CI/CD key).
          </p>
          <div className="flex flex-col gap-2">
            <Label htmlFor="template-name">Name</Label>
            <Input id="template-name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="template-description">Description (optional)</Label>
            <Input
              id="template-description"
              value={description}
              maxLength={500}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleSave} disabled={saving || !name.trim()}>
            {saving ? "Saving…" : "Save template"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function RunTriggerPage() {
  const navigate = useNavigate();
  const { user, can, canInProject } = useAuth();
  // Filled in from a run (?from_run=, "Edit and run") or a template (?template=, to run or update it).
  const [searchParams] = useSearchParams();
  const fromRun = searchParams.get("from_run");
  const fromTemplate = searchParams.get("template");
  const [template, setTemplate] = React.useState<RunTemplate | null>(null);
  const [notes, setNotes] = React.useState<string[]>([]);
  // The target group to select once the prefilled inventory's targets have loaded.
  const pendingGroup = React.useRef<string | null>(null);
  const [saveOpen, setSaveOpen] = React.useState(false);

  const [playbooks, setPlaybooks] = React.useState<PlaybookSummary[]>([]);
  const [inventories, setInventories] = React.useState<InventorySummary[]>([]);
  const [credentials, setCredentials] = React.useState<Credential[]>([]);
  const [vaultPasswords, setVaultPasswords] = React.useState<VaultPassword[]>([]);
  const [selectedInventory, setSelectedInventory] = React.useState<InventoryTargets | null>(null);

  // "Run" on a playbook opens this form with it picked (?playbook=<id>).
  const [playbookId, setPlaybookId] = React.useState<string>(() => searchParams.get("playbook") ?? "");
  const [inventoryId, setInventoryId] = React.useState<string>("");
  const [groupId, setGroupId] = React.useState<string>(ALL_HOSTS);
  const [credentialId, setCredentialId] = React.useState<string>("");
  const [vaultPasswordId, setVaultPasswordId] = React.useState<string>(NO_VAULT);
  const [become, setBecome] = React.useState(false);
  const [becomeConfirmed, setBecomeConfirmed] = React.useState(false);
  const [checkMode, setCheckMode] = React.useState(false);
  const [diffMode, setDiffMode] = React.useState(false);
  const [limit, setLimit] = React.useState("");
  const [timeoutMinutes, setTimeoutMinutes] = React.useState(String(DEFAULT_TIMEOUT_MINUTES));
  const [extraVarsText, setExtraVarsText] = React.useState("{}");
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  React.useEffect(() => {
    api.listPlaybooks().then(setPlaybooks);
    api.listInventories().then(setInventories);
    api.listCredentials("ssh").then(setCredentials);
    api.listVaultPasswords().then(setVaultPasswords);
  }, []);

  // A run lives in exactly one project: the playbook's. Only offer that project's items. When there's
  // just one choice, it's picked (until someone picks something else).
  const playbookChoice = playbookId || only(playbooks.filter((p) => p.missing_at === null));
  const playbookProjectId = playbooks.find((p) => String(p.id) === playbookChoice)?.project_id;
  const inProject = <T extends { project_id: number }>(items: T[]) =>
    playbookProjectId === undefined ? items : items.filter((i) => i.project_id === playbookProjectId);
  const inventoryChoice = inventoryId || only(inProject(inventories));
  const credentialChoice = credentialId || only(inProject(credentials));

  React.useEffect(() => {
    if (!inventoryChoice) {
      // oxlint-disable-next-line react/set-state-in-effect -- clearing the inventory clears its targets
      setSelectedInventory(null);
      return;
    }
    setGroupId(ALL_HOSTS);
    api.inventoryTargets(Number(inventoryChoice)).then((targets) => {
      setSelectedInventory(targets);
      const wanted = pendingGroup.current;
      pendingGroup.current = null;
      if (wanted === null) return;
      if (targets.groups.some((group) => group.name === wanted)) setGroupId(GROUP_PREFIX + wanted);
      else setNotes((current) => [...current, `The group ${wanted} is no longer in this inventory: pick a target.`]);
    });
  }, [inventoryChoice]);

  React.useEffect(() => {
    if (!fromRun && !fromTemplate) return;
    let active = true;

    function prefill(from: Run | RunTemplate, missing: string[]) {
      setPlaybookId(from.playbook_id === null ? "" : String(from.playbook_id));
      pendingGroup.current = from.group_name;
      setInventoryId(from.inventory_id === null ? "" : String(from.inventory_id));
      setCredentialId(from.credential_id === null ? "" : String(from.credential_id));
      setVaultPasswordId(from.vault_password_id === null ? NO_VAULT : String(from.vault_password_id));
      setCheckMode(from.check_mode);
      setDiffMode(from.diff_mode);
      setLimit(from.limit ?? "");
      setTimeoutMinutes(String(Math.max(1, Math.ceil(from.timeout_seconds / 60))));
      setExtraVarsText(from.extra_vars ? JSON.stringify(from.extra_vars, null, 2) : "{}");
      const found: string[] = [];
      if (missing.length > 0) found.push(`Pick again: ${describeDeleted(missing)}.`);
      if (from.become) {
        if (canInProject(from.project_id, "runs:become")) setBecome(true);
        else found.push("It ran as root (become), which you may not use: this run won't.");
      }
      if (hasMaskedValue(from.extra_vars)) {
        found.push(
          "Some extra vars show [REDACTED] or [HIDDEN] instead of their value: replace them before triggering " +
            "the run.",
        );
      }
      setNotes(found);
    }

    async function load() {
      try {
        if (fromTemplate) {
          const loaded = await api.getRunTemplate(Number(fromTemplate));
          if (!active) return;
          setTemplate(loaded);
          prefill(loaded, loaded.missing);
        } else {
          const loaded = await api.getRun(Number(fromRun));
          if (active) prefill(loaded, deletedItems(loaded));
        }
      } catch (err) {
        if (active) setError(err instanceof ApiError ? err.message : "Something went wrong");
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [fromRun, fromTemplate, canInProject]);

  function handlePlaybookChange(value: string) {
    const next = playbooks.find((p) => String(p.id) === value)?.project_id;
    if (next !== playbookProjectId) {
      setInventoryId("");
      setGroupId(ALL_HOSTS);
      setCredentialId("");
      setVaultPasswordId(NO_VAULT);
    }
    setPlaybookId(value);
  }

  const picked = playbookChoice !== "" && inventoryChoice !== "" && credentialChoice !== "";
  const canSubmit = picked && (!become || becomeConfirmed);

  const canSaveTemplate =
    picked &&
    playbookProjectId !== undefined &&
    canInProject(playbookProjectId, "content:write");
  const canUpdateTemplate = template !== null && canSaveTemplate && template.project_id === playbookProjectId;

  /** The form as a run request, or an error message if part of it isn't valid. */
  function buildRequest(): RunRequest | string {
    let extraVars: Record<string, unknown> | null;
    try {
      const parsed = JSON.parse(extraVarsText);
      extraVars = Object.keys(parsed).length > 0 ? parsed : null;
    } catch {
      return "Extra vars must be valid JSON";
    }

    const minutes = Number(timeoutMinutes);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > MAX_TIMEOUT_MINUTES) {
      return `Timeout must be a whole number of minutes from 1 to ${MAX_TIMEOUT_MINUTES}`;
    }

    return {
      playbook_id: Number(playbookChoice),
      inventory_id: Number(inventoryChoice),
      group_name: groupId === ALL_HOSTS ? null : groupId.slice(GROUP_PREFIX.length),
      credential_id: Number(credentialChoice),
      vault_password_id: vaultPasswordId === NO_VAULT ? null : Number(vaultPasswordId),
      become,
      check_mode: checkMode,
      diff_mode: diffMode,
      limit: limit.trim() || null,
      extra_vars: extraVars,
      timeout_seconds: minutes * 60,
    };
  }

  async function handleSubmit() {
    setError(null);
    const request = buildRequest();
    if (typeof request === "string") {
      setError(request);
      return;
    }
    if (hasMaskedValue(request.extra_vars)) {
      setError(
        "Extra vars still contain [REDACTED] or [HIDDEN]: enter the real values" +
          (template ? ", or run the template from the Templates page, which keeps them." : "."),
      );
      return;
    }

    setSubmitting(true);
    try {
      const run = await api.createRun(request);
      navigate(`/runs/${run.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  /** Saves the form as a new template; returns the reason it couldn't, for the dialog. */
  async function handleSaveTemplate(name: string, description: string | null): Promise<string | null> {
    const request = buildRequest();
    if (typeof request === "string") return request;
    try {
      await api.createRunTemplate({ ...request, name, description });
    } catch (err) {
      return err instanceof ApiError ? err.message : "Something went wrong";
    }
    navigate("/templates");
    return null;
  }

  async function handleUpdateTemplate() {
    if (!template) return;
    setError(null);
    const request = buildRequest();
    if (typeof request === "string") {
      setError(request);
      return;
    }
    setSubmitting(true);
    try {
      // Masked extra vars sent back unchanged keep their stored values.
      await api.updateRunTemplate(template.id, { ...request, name: template.name, description: template.description });
      navigate("/templates");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">New run</h1>
        {template && (
          <p className="text-sm text-muted-foreground">
            From the template <span className="font-medium text-foreground">{template.name}</span>: change what you
            need, then trigger the run or update the template.
          </p>
        )}
        {fromRun && !template && <p className="text-sm text-muted-foreground">Filled in from run #{fromRun}.</p>}
        {notes.map((note) => (
          <p key={note} className="text-sm text-status-changed">
            {note}
          </p>
        ))}
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="run-playbook">Playbook</Label>
        <Select value={playbookChoice} onValueChange={handlePlaybookChange}>
          <SelectTrigger id="run-playbook">
            <SelectValue placeholder="Select a playbook" />
          </SelectTrigger>
          <SelectContent>
            {playbooks
              .filter((playbook) => playbook.missing_at === null)
              .map((playbook) => (
                <SelectItem key={playbook.id} value={String(playbook.id)}>
                  {playbook.name}
                  {playbook.source_name && ` (git: ${playbook.source_name})`}
                </SelectItem>
              ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="run-inventory">Inventory</Label>
        <Select value={inventoryChoice} onValueChange={setInventoryId}>
          <SelectTrigger id="run-inventory">
            <SelectValue placeholder="Select an inventory" />
          </SelectTrigger>
          <SelectContent>
            {inProject(inventories).map((inventory) => (
              <SelectItem key={inventory.id} value={String(inventory.id)}>
                {inventory.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {selectedInventory && (
        <div className="flex flex-col gap-2">
          <Label htmlFor="run-target">Target</Label>
          <Select value={groupId} onValueChange={setGroupId}>
            <SelectTrigger id="run-target">
              <SelectValue placeholder="All hosts" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_HOSTS}>All hosts ({selectedInventory.hosts})</SelectItem>
              {selectedInventory.groups.map((group) => (
                <SelectItem key={group.name} value={GROUP_PREFIX + group.name}>
                  Group: {group.name} ({group.hosts}){group.origin === "source" ? " · from a source" : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <SnapshotNote targets={selectedInventory} />
        </div>
      )}

      <div className="flex flex-col gap-2">
        <Label htmlFor="run-credential">Credential</Label>
        <Select value={credentialChoice} onValueChange={setCredentialId}>
          <SelectTrigger id="run-credential">
            <SelectValue placeholder="Select a credential" />
          </SelectTrigger>
          <SelectContent>
            {inProject(credentials).map((credential) => (
              <SelectItem key={credential.id} value={String(credential.id)}>
                {credential.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="run-vault-password">Vault password (optional)</Label>
        <Select value={vaultPasswordId} onValueChange={setVaultPasswordId}>
          <SelectTrigger id="run-vault-password">
            <SelectValue placeholder="None" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={NO_VAULT}>None</SelectItem>
            {inProject(vaultPasswords).map((vaultPassword) => (
              <SelectItem key={vaultPassword.id} value={String(vaultPassword.id)}>
                {vaultPassword.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          Needed only if the playbook or extra vars contain Ansible Vault-encrypted values.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="run-limit">Limit (optional)</Label>
        <Input
          id="run-limit"
          placeholder="e.g. webservers[0], host1:host2, !excluded"
          value={limit}
          onChange={(e) => setLimit(e.target.value)}
        />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="run-timeout">Timeout (minutes)</Label>
        <Input
          id="run-timeout"
          type="number"
          min={1}
          max={MAX_TIMEOUT_MINUTES}
          step={1}
          className="w-40"
          value={timeoutMinutes}
          onChange={(e) => setTimeoutMinutes(e.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          The run is stopped (timed out) after running this long. Time spent queued doesn't count. At most 24
          hours.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={checkMode} onCheckedChange={(checked) => setCheckMode(checked === true)} />
          Check mode (dry run — report changes without making them)
        </label>
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={diffMode} onCheckedChange={(checked) => setDiffMode(checked === true)} />
          Diff mode (show before/after differences)
        </label>
      </div>

      <div className="flex flex-col gap-2">
        <Label id="run-extra-vars-label">Extra vars (JSON)</Label>
        <CodeEditor
          labelledBy="run-extra-vars-label"
          value={extraVarsText}
          onChange={setExtraVarsText}
          className="[&_.cm-editor]:min-h-24"
        />
      </div>

      {can("runs:become") && (
        <div className="flex flex-col gap-3 rounded-md border border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Run as admin (become root)</p>
              <p className="text-xs text-muted-foreground">Escalates privileges on the target host(s).</p>
            </div>
            <Switch
              aria-label="Run as admin (become root)"
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
      )}

      {error && <p className="text-sm text-destructive">{error}</p>}

      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={handleSubmit} disabled={!canSubmit || submitting} aria-describedby="start-run-hint">
          {submitting ? "Starting…" : "Start run"}
        </Button>
        {canUpdateTemplate && (
          <Button variant="outline" onClick={handleUpdateTemplate} disabled={submitting}>
            Update template
          </Button>
        )}
        {canSaveTemplate && (
          <Button variant="outline" onClick={() => setSaveOpen(true)} disabled={submitting}>
            Save as template
          </Button>
        )}
      </div>
      {!canSubmit && (
        <p id="start-run-hint" className="-mt-3 text-xs text-muted-foreground">
          {!picked
            ? "Pick a playbook, an inventory and a credential to start a run."
            : "Tick the root confirmation above to start this run."}
        </p>
      )}
      <SaveTemplateDialog open={saveOpen} onOpenChange={setSaveOpen} onSave={handleSaveTemplate} />
    </div>
  );
}
