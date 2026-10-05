import * as React from "react";
import { Link, useNavigate } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, type RunTemplate } from "@/lib/api";
import { describeDeleted } from "@/lib/runs";
import { useConfirmedAction } from "@/lib/use-confirmed-action";

/** Starts a run from the template; the limit and check mode may be changed for this run only. */
function LaunchDialog({ template, onOpenChange }: { template: RunTemplate; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate();
  const [limit, setLimit] = React.useState(template.limit ?? "");
  const [checkMode, setCheckMode] = React.useState(template.check_mode);
  const [error, setError] = React.useState<string | null>(null);
  const [starting, setStarting] = React.useState(false);

  async function handleLaunch() {
    setError(null);
    setStarting(true);
    try {
      const run = await api.launchRunTemplate(template.id, { limit: limit.trim(), check_mode: checkMode });
      navigate(`/runs/${run.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
      setStarting(false);
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Run {template.name}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            {template.playbook_name} on {template.inventory_name}
            {template.group_name ? ` / ${template.group_name}` : ""}, with the template&apos;s credential, options and
            extra vars. The playbook and inventory are used as they are now.
          </p>
          <div className="flex flex-col gap-2">
            <Label htmlFor="launch-limit">Limit (optional, this run only)</Label>
            <Input
              id="launch-limit"
              placeholder="e.g. webservers[0], host1:host2, !excluded"
              value={limit}
              onChange={(e) => setLimit(e.target.value)}
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={checkMode} onCheckedChange={(checked) => setCheckMode(checked === true)} />
            Check mode (dry run — report changes without making them)
          </label>
          {template.become && (
            <p className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
              This template runs with root privileges (become) on the target host(s).
            </p>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleLaunch} disabled={starting}>
            {starting ? "Starting…" : template.become ? "Run as root" : "Run"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function TemplateCard({
  template,
  onLaunch,
  onDelete,
}: {
  template: RunTemplate;
  onLaunch: () => void;
  onDelete: () => void;
}) {
  const { canInProject } = useAuth();
  const canRun = canInProject(template.project_id, "runs:trigger");
  const canEdit = canInProject(template.project_id, "content:write");
  const missing = template.missing.length > 0;
  const options = [
    template.become && "become",
    template.check_mode && "check",
    template.diff_mode && "diff",
    template.limit && `limit: ${template.limit}`,
    template.vault_password_name && `vault: ${template.vault_password_name}`,
  ].filter(Boolean);

  return (
    <Card>
      <CardContent className="flex flex-wrap items-start justify-between gap-4 pt-6">
        <div className="flex min-w-0 flex-col gap-1">
          <h2 className="flex items-center gap-2 font-medium">
            {template.name}
            {template.become && <Badge variant="failed">root</Badge>}
          </h2>
          {template.description && <p className="text-sm text-muted-foreground">{template.description}</p>}
          <p className="text-sm text-muted-foreground">
            {template.playbook_name ?? "(deleted playbook)"} → {template.inventory_name ?? "(deleted inventory)"}
            {template.group_name ? ` / ${template.group_name}` : ""} · credential{" "}
            {template.credential_name ?? "(deleted)"}
            {options.length > 0 && ` · ${options.join(" · ")}`}
          </p>
          {missing && (
            <p className="text-sm text-destructive">
              Can&apos;t run: {describeDeleted(template.missing)}.{canEdit ? " Edit it to pick another." : ""}
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            Saved by {template.updated_by}, {new Date(template.updated_at).toLocaleString()}
          </p>
        </div>
        <div className="flex gap-2">
          {canRun && (
            <Button size="sm" onClick={onLaunch} disabled={missing}>
              Run
            </Button>
          )}
          {canEdit && (
            <>
              <Button size="sm" variant="outline" asChild>
                <Link to={`/runs/new?template=${template.id}`} aria-label={`Edit ${template.name}`}>
                  Edit
                </Link>
              </Button>
              <Button size="sm" variant="outline" onClick={onDelete} aria-label={`Delete ${template.name}`}>
                Delete
              </Button>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export function TemplatesPage() {
  const { can, activeProjectId } = useAuth();
  const [templates, setTemplates] = React.useState<RunTemplate[] | null>(null);
  const [launching, setLaunching] = React.useState<RunTemplate | null>(null);

  const refresh = React.useCallback(() => {
    api.listRunTemplates().then(setTemplates);
  }, []);
  React.useEffect(refresh, [refresh, activeProjectId]);
  const deletion = useConfirmedAction(refresh);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Run templates</h1>
          <p className="text-sm text-muted-foreground">
            Saved runs, started again in one step. Save one from the New Run form.
          </p>
        </div>
        {can("runs:trigger") && (
          <Button asChild>
            <Link to="/runs/new">New Run</Link>
          </Button>
        )}
      </div>

      {deletion.error && <p className="text-sm text-destructive">{deletion.error}</p>}

      {templates === null ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : templates.length === 0 ? (
        <p className="text-sm text-muted-foreground">No templates yet.</p>
      ) : (
        <div className="flex flex-col gap-3">
          {templates.map((template) => (
            <TemplateCard
              key={template.id}
              template={template}
              onLaunch={() => setLaunching(template)}
              onDelete={() =>
                deletion.run(`Delete the template "${template.name}"? Runs started from it are kept.`, () =>
                  api.deleteRunTemplate(template.id),
                )
              }
            />
          ))}
        </div>
      )}

      {launching && (
        <LaunchDialog
          template={launching}
          onOpenChange={(open) => {
            if (!open) setLaunching(null);
          }}
        />
      )}
    </div>
  );
}
