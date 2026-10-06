import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
  type GitAuthKind,
  type GitSource,
  type GitSourceInput,
  type GitTestResult,
} from "@/lib/api";
import { commitLink, isSshUrl, shortSha } from "@/lib/git";

const INTERVALS: { value: number; label: string }[] = [
  { value: 0, label: "Manual only (Sync now)" },
  { value: 60, label: "Every minute" },
  { value: 300, label: "Every 5 minutes" },
  { value: 900, label: "Every 15 minutes" },
  { value: 3600, label: "Every hour" },
];
const DEFAULT_GLOBS = "*.yml, *.yaml, playbooks/*.yml, playbooks/*.yaml";

function errorMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : "Something went wrong";
}

function syncing(source: GitSource): boolean {
  return source.sync_requested_at !== null || source.last_sync_status === "running";
}

function StatusBadge({ source }: { source: GitSource }) {
  if (!source.enabled) return <Badge variant="outline">off</Badge>;
  if (syncing(source)) return <Badge variant="changed">syncing</Badge>;
  if (source.last_sync_status === "ok") return <Badge variant="ok">synced</Badge>;
  if (source.last_sync_status === "failed") return <Badge variant="failed">failed</Badge>;
  return <Badge variant="outline">not synced</Badge>;
}

/** The project's git sources, above its playbooks. Polls while a sync is under way. */
export function GitSourcesPanel({ projectId, onSynced }: { projectId: number; onSynced: () => void }) {
  const { canInProject } = useAuth();
  const canManage = canInProject(projectId, "sources:manage");
  const [sources, setSources] = React.useState<GitSource[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [adding, setAdding] = React.useState(false);
  const wasSyncing = React.useRef(false);

  const refresh = React.useCallback(() => {
    api
      .listGitSources(projectId)
      .then((list) => {
        setSources(list);
        const busy = list.some(syncing);
        if (wasSyncing.current && !busy) onSynced(); // a sync finished: playbooks changed
        wasSyncing.current = busy;
      })
      .catch((err) => setError(errorMessage(err)));
  }, [projectId, onSynced]);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  const busy = sources.some(syncing);
  React.useEffect(() => {
    if (!busy) return;
    const timer = window.setInterval(refresh, 3000);
    return () => window.clearInterval(timer);
  }, [busy, refresh]);

  if (!canManage && sources.length === 0 && !error) return null;

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold">Git sources</h2>
          <p className="text-sm text-muted-foreground">
            Playbooks synced from a repository are read-only here: change them in the repository. Runs execute
            inside the repository at the commit current when they start.
          </p>
        </div>
        {canManage && (
          <Button size="sm" variant="outline" onClick={() => setAdding(true)}>
            Add git source
          </Button>
        )}
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      {sources.map((source) => (
        <SourceCard
          key={source.id}
          projectId={projectId}
          source={source}
          canManage={canManage}
          onChanged={refresh}
        />
      ))}
      <SourceDialog
        open={adding}
        onOpenChange={setAdding}
        projectId={projectId}
        source={null}
        onSaved={refresh}
      />
    </section>
  );
}

function SourceCard({
  projectId,
  source,
  canManage,
  onChanged,
}: {
  projectId: number;
  source: GitSource;
  canManage: boolean;
  onChanged: () => void;
}) {
  const { canInProject } = useAuth();
  const canSync = canInProject(projectId, "content:write");
  const [editing, setEditing] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState<string | null>(null);
  const [test, setTest] = React.useState<GitTestResult | null>(null);
  const [pasting, setPasting] = React.useState(false);
  const [knownHosts, setKnownHosts] = React.useState("");
  const link = commitLink(source.web_url, source.commit);

  async function act(action: () => Promise<unknown>) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      onChanged();
    } catch (err) {
      setMessage(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleTest() {
    setBusy(true);
    setMessage(null);
    setTest(null);
    try {
      setTest(await api.testGitSource(projectId, source.id));
    } catch (err) {
      setMessage(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function trust(trustInput: { fingerprint?: string; known_hosts?: string }) {
    await act(async () => {
      await api.trustGitHostKey(projectId, source.id, trustInput);
      setTest(null);
      setPasting(false);
      setKnownHosts("");
    });
  }

  const needsKey = isSshUrl(source.url) && source.host_keys.length === 0;
  return (
    <Card>
      <CardContent className="flex flex-col gap-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="font-medium">{source.name}</span>
            <StatusBadge source={source} />
            <span className="truncate font-mono text-xs text-muted-foreground" title={source.url}>
              {source.url}
            </span>
            <Badge variant="outline">{source.branch}</Badge>
            {source.subdir && <Badge variant="outline">{source.subdir}/</Badge>}
          </div>
          <div className="flex flex-wrap gap-2">
            {canSync && (
              <Button
                size="sm"
                disabled={busy || !source.enabled || syncing(source) || needsKey}
                onClick={() => act(() => api.syncGitSource(projectId, source.id))}
              >
                {syncing(source) ? "Syncing…" : "Sync now"}
              </Button>
            )}
            {canManage && (
              <>
                <Button variant="outline" size="sm" disabled={busy} onClick={handleTest}>
                  Test connection
                </Button>
                <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
                  Edit
                </Button>
                <Button
                  variant="destructive-outline"
                  size="sm"
                  disabled={busy}
                  onClick={() => {
                    if (
                      window.confirm(
                        `Delete the git source "${source.name}"? Its ${source.playbooks} synced playbooks go too (run history stays).`,
                      )
                    ) {
                      act(() => api.deleteGitSource(projectId, source.id));
                    }
                  }}
                >
                  Delete
                </Button>
              </>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground">
          {source.commit ? (
            <>
              <span>Commit</span>
              {link ? (
                <a
                  href={link}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="font-mono text-primary hover:underline"
                >
                  {shortSha(source.commit)}
                </a>
              ) : (
                <span className="font-mono text-foreground">{shortSha(source.commit)}</span>
              )}
              {source.commit_subject && <span className="truncate">“{source.commit_subject}”</span>}
              <span>
                · {source.playbooks} playbook{source.playbooks === 1 ? "" : "s"}
                {source.missing_playbooks > 0 && `, ${source.missing_playbooks} removed upstream`}
              </span>
            </>
          ) : (
            <span>Not synced yet.</span>
          )}
          {source.last_sync_finished_at && (
            <span>· last sync {new Date(source.last_sync_finished_at).toLocaleString()}</span>
          )}
          <span>
            ·{" "}
            {source.auto_sync_seconds === 0
              ? "manual syncs only"
              : (INTERVALS.find((i) => i.value === source.auto_sync_seconds)?.label.toLowerCase() ??
                `every ${source.auto_sync_seconds} s`)}
          </span>
        </div>

        {needsKey && (
          <p className="text-sm text-status-changed">
            {canManage
              ? "Test the connection and trust the server's SSH host key before the first sync."
              : "Waiting for a project admin to trust the server's SSH host key."}
          </p>
        )}
        {source.last_sync_status === "failed" && source.last_sync_error && (
          <p className="whitespace-pre-wrap break-words font-mono text-xs text-destructive">
            {source.last_sync_error}
          </p>
        )}
        {source.warnings.map((warning) => (
          <p key={warning} className="text-xs text-status-changed">
            {warning}
          </p>
        ))}
        {message && <p className="text-sm text-destructive">{message}</p>}

        {test && (
          <div className="flex flex-col gap-2 rounded-md border border-border p-3 text-sm">
            {test.host_keys.length > 0 && (
              <div className="flex flex-col gap-1">
                <span className="text-muted-foreground">
                  Host keys the server presented. Compare a fingerprint with the one your forge publishes
                  before you trust it.
                </span>
                {test.host_keys.map((key) => (
                  <div key={key.fingerprint} className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline">{key.type}</Badge>
                    <span className="font-mono text-xs">{key.fingerprint}</span>
                    {key.trusted ? (
                      <Badge variant="ok">trusted</Badge>
                    ) : (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        onClick={() => trust({ fingerprint: key.fingerprint })}
                      >
                        Trust
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            )}
            {test.ok ? (
              <p className="text-status-ok">
                Connected: branch “{source.branch}” exists
                {test.default_branch && ` (the default branch is “${test.default_branch}”)`}.
              </p>
            ) : (
              <p className="text-destructive">{test.error ?? "The connection failed."}</p>
            )}
          </div>
        )}
        {canManage && isSshUrl(source.url) && (
          <div className="text-sm">
            {source.host_keys.length > 0 && (
              <p className="text-muted-foreground">
                Trusted host key{source.host_keys.length === 1 ? "" : "s"}:{" "}
                {source.host_keys.map((k) => (
                  <span key={k.fingerprint} className="mr-2 font-mono text-xs">
                    {k.type} {k.fingerprint}
                  </span>
                ))}
              </p>
            )}
            <button
              type="button"
              className="text-primary hover:underline"
              onClick={() => setPasting((v) => !v)}
            >
              {pasting ? "Cancel" : "Paste a known_hosts line instead"}
            </button>
            {pasting && (
              <div className="mt-2 flex flex-col gap-2">
                <Textarea
                  value={knownHosts}
                  onChange={(e) => setKnownHosts(e.target.value)}
                  placeholder="git.example.com ssh-ed25519 AAAA…"
                  className="min-h-20 font-mono text-xs"
                  spellCheck={false}
                />
                <div>
                  <Button
                    size="sm"
                    disabled={busy || !knownHosts.trim()}
                    onClick={() => trust({ known_hosts: knownHosts })}
                  >
                    Trust these keys
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
      <SourceDialog
        open={editing}
        onOpenChange={setEditing}
        projectId={projectId}
        source={source}
        onSaved={onChanged}
      />
    </Card>
  );
}

function SourceDialog({
  open,
  onOpenChange,
  projectId,
  source,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: number;
  source: GitSource | null;
  onSaved: () => void;
}) {
  const [name, setName] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [branch, setBranch] = React.useState("main");
  const [subdir, setSubdir] = React.useState("");
  const [globs, setGlobs] = React.useState(DEFAULT_GLOBS);
  const [chosenAuth, setAuth] = React.useState<GitAuthKind>("none");
  const [credentialId, setCredentialId] = React.useState<string>("");
  const [username, setUsername] = React.useState("");
  const [token, setToken] = React.useState("");
  const [interval, setSyncInterval] = React.useState(300);
  const [webUrl, setWebUrl] = React.useState("");
  const [enabled, setEnabled] = React.useState(true);
  const [credentials, setCredentials] = React.useState<Credential[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (!open) return;
    // oxlint-disable-next-line react/set-state-in-effect -- opening the dialog resets the form to the source
    setName(source?.name ?? "");
    setUrl(source?.url ?? "");
    setBranch(source?.branch ?? "main");
    setSubdir(source?.subdir ?? "");
    setGlobs(source ? source.playbook_globs.join(", ") : DEFAULT_GLOBS);
    setAuth(source?.auth_kind ?? "none");
    setCredentialId(source?.credential_id ? String(source.credential_id) : "");
    setUsername(source?.https_username ?? "");
    setToken("");
    setSyncInterval(source?.auto_sync_seconds ?? 300);
    setWebUrl(source?.web_url ?? "");
    setEnabled(source?.enabled ?? true);
    setError(null);
    api
      .listCredentials()
      .then((list) => setCredentials(list.filter((c) => c.project_id === projectId)))
      .catch(() => setCredentials([]));
  }, [open, source, projectId]);

  const ssh = isSshUrl(url);
  // The URL decides what kind of authentication fits.
  const auth: GitAuthKind = ssh ? "ssh_key" : chosenAuth === "ssh_key" ? "none" : chosenAuth;

  async function handleSave() {
    setError(null);
    setSaving(true);
    const input: GitSourceInput = {
      name: name.trim(),
      url: url.trim(),
      branch: branch.trim() || "main",
      subdir: subdir.trim() || null,
      web_url: webUrl.trim() || null,
      playbook_globs: globs
        .split(/[\n,]/)
        .map((g) => g.trim())
        .filter(Boolean),
      auth_kind: auth,
      credential_id: auth === "ssh_key" && credentialId ? Number(credentialId) : null,
      https_username: auth === "https_token" ? username.trim() || null : null,
      auto_sync_seconds: interval,
      enabled,
    };
    if (auth === "https_token" && token) input.token = token;
    try {
      if (source) await api.updateGitSource(projectId, source.id, input);
      else await api.createGitSource(projectId, input);
      onOpenChange(false);
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  const plainHttp = url.trim().startsWith("http://");
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{source ? `Edit ${source.name}` : "Add a git source"}</DialogTitle>
          <DialogDescription>
            AnsiDeck fetches the branch's latest commit; matching playbook files appear read-only. Tokens are
            stored encrypted and never shown again.
          </DialogDescription>
        </DialogHeader>
        <div className="-mx-1 flex max-h-[65vh] flex-col gap-4 overflow-y-auto px-1">
          <div className="flex flex-col gap-2">
            <Label htmlFor="source-name">Name</Label>
            <Input id="source-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="source-url">Repository URL</Label>
            <Input
              id="source-url"
              value={url}
              placeholder="https://github.com/org/playbooks.git or git@gitea.lan:org/playbooks.git"
              onChange={(e) => setUrl(e.target.value)}
              className="font-mono"
            />
            {source && url.trim() !== source.url && isSshUrl(url) && (
              <p className="text-xs text-status-changed">A new host needs its SSH host key trusted again.</p>
            )}
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-2">
              <Label htmlFor="source-branch">Branch</Label>
              <Input id="source-branch" value={branch} onChange={(e) => setBranch(e.target.value)} />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="source-subdir">Subdirectory (optional)</Label>
              <Input
                id="source-subdir"
                value={subdir}
                placeholder="ansible"
                onChange={(e) => setSubdir(e.target.value)}
              />
            </div>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="source-globs">Playbook files</Label>
            <Input
              id="source-globs"
              value={globs}
              onChange={(e) => setGlobs(e.target.value)}
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated patterns, relative to the repository (or subdirectory). * stays within a
              directory, ** spans directories. Only files that are playbooks are listed.
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="source-auth">Authentication</Label>
            <Select value={auth} onValueChange={(value) => setAuth(value as GitAuthKind)}>
              <SelectTrigger id="source-auth">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none" disabled={ssh}>
                  None (public repository)
                </SelectItem>
                <SelectItem value="https_token" disabled={ssh}>
                  User name and token (HTTPS)
                </SelectItem>
                <SelectItem value="ssh_key" disabled={!ssh}>
                  SSH deploy key
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          {auth === "ssh_key" && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="source-credential">Deploy key</Label>
              <Select value={credentialId} onValueChange={setCredentialId}>
                <SelectTrigger id="source-credential">
                  <SelectValue placeholder="Pick one of the project's SSH keys" />
                </SelectTrigger>
                <SelectContent>
                  {credentials.map((c) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Add the key's public half to the repository as a read-only deploy key.
              </p>
            </div>
          )}
          {auth === "https_token" && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="flex flex-col gap-2">
                <Label htmlFor="source-username">User name</Label>
                <Input id="source-username" value={username} onChange={(e) => setUsername(e.target.value)} />
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="source-token">Token</Label>
                <Input
                  id="source-token"
                  type="password"
                  autoComplete="off"
                  value={token}
                  placeholder={source?.has_token ? "Leave empty to keep the current one" : undefined}
                  onChange={(e) => setToken(e.target.value)}
                />
              </div>
              {plainHttp && (
                <p className="text-xs text-status-changed sm:col-span-2">
                  Plain http:// sends the token unencrypted; only use it on a private network.
                </p>
              )}
            </div>
          )}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-2">
              <Label htmlFor="source-interval">Sync</Label>
              <Select value={String(interval)} onValueChange={(value) => setSyncInterval(Number(value))}>
                <SelectTrigger id="source-interval">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INTERVALS.map((i) => (
                    <SelectItem key={i.value} value={String(i.value)}>
                      {i.label}
                    </SelectItem>
                  ))}
                  {!INTERVALS.some((i) => i.value === interval) && (
                    <SelectItem value={String(interval)}>Every {interval} s</SelectItem>
                  )}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="source-web">Web URL for commit links (optional)</Label>
              <Input
                id="source-web"
                value={webUrl}
                placeholder="https://github.com/org/playbooks"
                onChange={(e) => setWebUrl(e.target.value)}
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Switch
              id="source-enabled"
              className="data-[state=checked]:bg-primary"
              checked={enabled}
              onCheckedChange={setEnabled}
            />
            <Label htmlFor="source-enabled">Sync this source</Label>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            disabled={saving || !name.trim() || !url.trim() || (auth === "ssh_key" && !credentialId)}
          >
            {saving ? "Saving…" : source ? "Save" : "Add source"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
