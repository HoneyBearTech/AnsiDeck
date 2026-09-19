import * as React from "react";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/context/auth-context";
import {
  api,
  ApiError,
  type GalaxyInstall,
  type GalaxyInstalled,
  type GalaxyInstallDetail,
  type GalaxyItem,
} from "@/lib/api";

const STATUS_VARIANT: Record<GalaxyInstall["status"], BadgeProps["variant"]> = {
  success: "ok",
  failed: "failed",
  running: "changed",
  queued: "skipped",
};

const REQUIREMENTS_PLACEHOLDER = `collections:
  - name: community.general
    version: ">=8.0.0"
roles:
  - name: geerlingguy.docker`;

function isActive(install: { status: GalaxyInstall["status"] } | null): boolean {
  return install?.status === "queued" || install?.status === "running";
}

function ItemList({ title, items }: { title: string; items: GalaxyItem[] }) {
  return (
    <div className="flex flex-col gap-2">
      <Label>{title}</Label>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">None installed.</p>
      ) : (
        <ul className="flex flex-col gap-1">
          {items.map((item) => (
            <li key={item.name} className="flex items-center justify-between text-sm">
              <span className="font-mono">{item.name}</span>
              <span className="text-xs text-muted-foreground">{item.version ?? "unknown version"}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function GalaxyPage() {
  const { can } = useAuth();
  const canManage = can("galaxy:manage");
  const [content, setContent] = React.useState("");
  const [savedContent, setSavedContent] = React.useState("");
  const [saveError, setSaveError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  const [confirmed, setConfirmed] = React.useState(false);
  const [upgrade, setUpgrade] = React.useState(false);
  const [installError, setInstallError] = React.useState<string | null>(null);
  const [starting, setStarting] = React.useState(false);
  const [current, setCurrent] = React.useState<GalaxyInstallDetail | null>(null);

  const [installed, setInstalled] = React.useState<GalaxyInstalled | null>(null);
  const [history, setHistory] = React.useState<GalaxyInstall[]>([]);

  const refreshInstalled = React.useCallback(() => {
    api.getGalaxyInstalled().then(setInstalled);
    api.listGalaxyInstalls().then(setHistory);
  }, []);

  React.useEffect(() => {
    api.getGalaxyRequirements().then((r) => {
      setContent(r.content);
      setSavedContent(r.content);
    });
    refreshInstalled();
  }, [refreshInstalled]);

  const currentId = current?.id;
  const currentActive = isActive(current);
  React.useEffect(() => {
    if (currentId === undefined || !currentActive) return;
    const timer = setInterval(() => {
      api.getGalaxyInstall(currentId).then((detail) => {
        setCurrent(detail);
        if (!isActive(detail)) refreshInstalled();
      });
    }, 1500);
    return () => clearInterval(timer);
  }, [currentId, currentActive, refreshInstalled]);

  async function handleSave() {
    setSaveError(null);
    setSaving(true);
    try {
      const saved = await api.saveGalaxyRequirements(content);
      setSavedContent(saved.content);
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSaving(false);
    }
  }

  async function handleInstall() {
    setInstallError(null);
    setStarting(true);
    try {
      setCurrent(await api.createGalaxyInstall(upgrade));
      setConfirmed(false);
    } catch (err) {
      setInstallError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setStarting(false);
    }
  }

  const dirty = content !== savedContent;

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">Galaxy</h1>

      {canManage && (
        <div className="flex flex-col gap-1 rounded-md bg-destructive/10 p-4">
          <p className="text-sm font-medium text-destructive">Installed content runs as code</p>
          <p className="text-sm text-destructive">
            Installing roles and collections downloads and runs third-party code. Modules and plugins run
            inside the AnsiDeck container and can access decrypted SSH keys and vault passwords whenever a
            playbook runs. Only install content you trust.
          </p>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Requirements</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="galaxy-requirements">requirements.yml</Label>
            <Textarea
              id="galaxy-requirements"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              className="min-h-48 font-mono"
              spellCheck={false}
              readOnly={!canManage}
              placeholder={REQUIREMENTS_PLACEHOLDER}
            />
            <p className="text-xs text-muted-foreground">
              Galaxy names, https:// URLs and git+https:// sources only. Local paths and other schemes are
              rejected.
            </p>
          </div>
          {saveError && <p className="text-sm text-destructive">{saveError}</p>}
          {canManage && (
            <div>
              <Button onClick={handleSave} disabled={saving || !dirty}>
                {saving ? "Saving…" : dirty ? "Save" : "Saved"}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {canManage && (
        <Card>
          <CardHeader>
            <CardTitle>Install</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <p className="text-sm text-muted-foreground">
              Installs the last saved requirements. Runs are blocked while an install is in progress, and
              installs wait for active runs to finish. Collections already bundled with AnsiDeck's Ansible are
              skipped unless you pin a newer version or tick upgrade below.
            </p>
            <div className="flex flex-col gap-2">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={upgrade} onCheckedChange={(c) => setUpgrade(c === true)} />
                Upgrade / reinstall items that are already installed
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={confirmed} onCheckedChange={(c) => setConfirmed(c === true)} />I understand
                this runs third-party code.
              </label>
            </div>
            {installError && <p className="text-sm text-destructive">{installError}</p>}
            <div>
              <Button onClick={handleInstall} disabled={!confirmed || starting || dirty || currentActive}>
                {starting ? "Starting…" : currentActive ? "Installing…" : "Install"}
              </Button>
              {dirty && <span className="ml-3 text-xs text-muted-foreground">Save your changes first.</span>}
            </div>

            {current && (
              <div className="flex flex-col gap-2 border-t border-border pt-4">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">Install #{current.id}</span>
                  <Badge variant={STATUS_VARIANT[current.status]}>{current.status}</Badge>
                </div>
                <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap">
                  {current.log || "Waiting for output…"}
                </pre>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Installed</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <ItemList title="Collections" items={installed?.collections ?? []} />
          <ItemList title="Roles" items={installed?.roles ?? []} />
        </CardContent>
      </Card>

      {history.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Install history</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {history.map((install) => (
              <button
                key={install.id}
                type="button"
                className="flex items-center justify-between rounded-md p-2 text-left text-sm hover:bg-muted"
                onClick={() => api.getGalaxyInstall(install.id).then(setCurrent)}
              >
                <span>
                  #{install.id} · {install.triggered_by} · {new Date(install.created_at).toLocaleString()}
                  {install.upgrade && " · upgrade"}
                </span>
                <Badge variant={STATUS_VARIANT[install.status]}>{install.status}</Badge>
              </button>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
