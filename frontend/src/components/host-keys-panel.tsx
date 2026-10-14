import * as React from "react";
import { Link } from "react-router-dom";

import { Badge, type BadgeProps } from "@/components/ui/badge";
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
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/context/auth-context";
import {
  api,
  ApiError,
  type HostKey,
  type HostKeyMode,
  type HostKeys,
  type HostKeyStatus,
  type PastedHostKey,
} from "@/lib/api";

const MODE_LABELS: Record<HostKeyMode, string> = {
  off: "Off: not checked",
  accept_new: "Learn new hosts",
  strict: "Strict: confirmed keys only",
};

const MODE_HELP: Record<HostKeyMode, string> = {
  off: "Runs don't check host keys: they talk to whatever answers at a host's address.",
  accept_new:
    "A host's key is learned on its first run; after that a run fails if the key changes. Learned keys are " +
    "trusted until removed; confirm them to keep them in strict mode too.",
  strict: "Only keys a project admin pasted or confirmed are trusted. A host without one fails its runs.",
};

const STATUS: Record<HostKeyStatus, { label: string; variant: BadgeProps["variant"] }> = {
  trusted: { label: "trusted", variant: "ok" },
  learned: { label: "learned, unconfirmed", variant: "changed" },
  missing: { label: "no key yet", variant: "outline" },
  unknown: { label: "address unknown", variant: "skipped" },
  not_checked: { label: "not ssh", variant: "skipped" },
};

const CHANGE_LABELS: Record<PastedHostKey["change"], string> = {
  new: "new",
  replace: "replaces a key",
  confirm: "confirms a learned key",
  same: "already trusted",
};

function errorMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : "Something went wrong";
}

function PasteDialog({
  inventoryId,
  open,
  onClose,
  onSaved,
}: {
  inventoryId: number;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [text, setText] = React.useState("");
  const [preview, setPreview] = React.useState<{ keys: PastedHostKey[]; warnings: string[] } | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);

  async function send(dryRun: boolean) {
    setBusy(true);
    setError(null);
    try {
      const result = await api.pasteHostKeys(inventoryId, text, dryRun);
      if (dryRun) {
        setPreview(result);
      } else {
        onSaved();
        onClose();
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const replacing = preview?.keys.some((k) => k.change === "replace");
  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Trust host keys</DialogTitle>
          <DialogDescription>
            Paste known_hosts lines, for example from <code>ssh-keyscan -p 22 web1.example.com</code> run
            somewhere you trust, or a host&apos;s own <code>/etc/ssh/ssh_host_*_key.pub</code> with its name
            in front. Hashed names, wildcards and @cert-authority lines aren&apos;t used.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-2">
          <Label htmlFor="known-hosts">known_hosts</Label>
          <Textarea
            id="known-hosts"
            rows={6}
            className="font-mono text-xs"
            placeholder="[10.0.0.5]:2222 ssh-ed25519 AAAA…"
            value={text}
            onChange={(event) => {
              setText(event.target.value);
              setPreview(null);
            }}
          />
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        {preview && (
          <div className="flex flex-col gap-2">
            <p className="text-sm font-medium">What changes</p>
            <ul className="flex flex-col gap-1 text-sm">
              {preview.keys.map((key) => (
                <li key={`${key.name} ${key.key_type}`} className="flex flex-col">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="font-mono wrap-anywhere">{key.name}</span>
                    <Badge variant="outline">{key.key_type}</Badge>
                    <Badge variant={key.change === "replace" ? "changed" : "default"}>
                      {CHANGE_LABELS[key.change]}
                    </Badge>
                    {key.hosts.length > 0 && (
                      <span className="text-xs text-muted-foreground wrap-anywhere">
                        {key.hosts.join(", ")}
                      </span>
                    )}
                  </span>
                  <span className="font-mono text-xs text-muted-foreground wrap-anywhere">
                    {key.fingerprint}
                  </span>
                  {key.previous && (
                    <span className="font-mono text-xs text-status-changed wrap-anywhere">
                      was {key.previous}
                    </span>
                  )}
                </li>
              ))}
            </ul>
            {preview.warnings.length > 0 && (
              <ul className="list-disc pl-5 text-xs text-status-changed">
                {preview.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        <DialogFooter>
          {preview ? (
            <Button onClick={() => send(false)} disabled={busy || preview.keys.length === 0}>
              {replacing ? "Trust and replace" : "Trust these keys"}
            </Button>
          ) : (
            <Button onClick={() => send(true)} disabled={busy || !text.trim()}>
              Preview
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function KeyRow({
  hostKey,
  canManage,
  onRemove,
}: {
  hostKey: HostKey;
  canManage: boolean;
  onRemove: (key: HostKey) => void;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border p-3">
      <div className="flex min-w-0 flex-col gap-1">
        <span className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm wrap-anywhere">{hostKey.name}</span>
          <Badge variant="outline">{hostKey.key_type}</Badge>
          {!hostKey.confirmed && <Badge variant="changed">unconfirmed</Badge>}
          {hostKey.hosts.length > 0 ? (
            <span className="text-xs text-muted-foreground wrap-anywhere">{hostKey.hosts.join(", ")}</span>
          ) : (
            <span className="text-xs text-muted-foreground">no host connects to it now</span>
          )}
        </span>
        <span className="font-mono text-xs wrap-anywhere">{hostKey.fingerprint}</span>
        <span className="text-xs text-muted-foreground">
          {hostKey.source === "learned" ? (
            <>
              learned{" "}
              {hostKey.run_id !== null ? (
                <Link to={`/runs/${hostKey.run_id}`}>by run #{hostKey.run_id}</Link>
              ) : null}
            </>
          ) : (
            <>
              {hostKey.source === "scan" ? "scanned" : "pasted"} by {hostKey.created_by}
            </>
          )}{" "}
          · {new Date(hostKey.created_at).toLocaleString()}
          {hostKey.confirmed_by && hostKey.source === "learned" && ` · confirmed by ${hostKey.confirmed_by}`}
        </span>
      </div>
      {canManage && (
        <Button size="sm" variant="destructive-outline" onClick={() => onRemove(hostKey)}>
          Remove
        </Button>
      )}
    </div>
  );
}

export function HostKeysPanel({
  inventoryId,
  projectId,
  onModeChanged,
}: {
  inventoryId: number;
  projectId: number;
  onModeChanged?: (mode: HostKeyMode) => void;
}) {
  const { canInProject } = useAuth();
  const canManage = canInProject(projectId, "sources:manage");
  const [data, setData] = React.useState<HostKeys | null>(null);
  const [query, setQuery] = React.useState("");
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const [pasting, setPasting] = React.useState(false);
  const error = actionError ?? loadError;

  const load = React.useCallback(() => {
    api
      .getHostKeys(inventoryId, query)
      .then((result) => {
        setData(result);
        setLoadError(null);
      })
      .catch((err) => setLoadError(errorMessage(err)));
  }, [inventoryId, query]);

  React.useEffect(() => {
    load();
  }, [load]);

  async function act(action: () => Promise<unknown>) {
    setActionError(null);
    try {
      await action();
    } catch (err) {
      setActionError(errorMessage(err));
    }
    load();
  }

  function changeMode(mode: HostKeyMode) {
    if (!data || mode === data.mode) return;
    const { summary } = data;
    if (
      mode === "off" &&
      !window.confirm("Stop checking host keys? Runs will talk to whatever answers at a host's address.")
    ) {
      return;
    }
    const unconfirmed = summary.learned + summary.missing;
    if (
      mode === "strict" &&
      unconfirmed > 0 &&
      !window.confirm(
        `${unconfirmed} host${unconfirmed === 1 ? " has" : "s have"} no confirmed key: their runs will fail until ` +
          "you trust or confirm one. Switch to strict?",
      )
    ) {
      return;
    }
    act(async () => {
      await api.setHostKeyMode(inventoryId, mode);
      onModeChanged?.(mode);
    });
  }

  if (!data) {
    return error ? <p className="text-sm text-destructive">{error}</p> : null;
  }
  const { summary } = data;
  const learned = data.keys.filter((k) => !k.confirmed);
  const counts = (Object.keys(STATUS) as HostKeyStatus[]).filter((status) => summary[status] > 0);

  return (
    <Card id="host-keys">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2">
        <div className="flex min-w-0 flex-col gap-1">
          <CardTitle>SSH host keys</CardTitle>
          <p className="text-sm text-muted-foreground">{MODE_HELP[data.mode]}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {canManage && learned.length > 0 && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                if (
                  window.confirm(
                    `Confirm ${learned.length} learned key${learned.length === 1 ? "" : "s"}? Check the ` +
                      "fingerprints against the hosts first if they matter to you.",
                  )
                ) {
                  act(() =>
                    api.confirmHostKeys(
                      inventoryId,
                      learned.map((k) => k.id),
                    ),
                  );
                }
              }}
            >
              Confirm learned ({learned.length})
            </Button>
          )}
          {canManage && (
            <Button size="sm" variant="outline" onClick={() => setPasting(true)}>
              Paste known_hosts
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {error && <p className="text-sm text-destructive">{error}</p>}
        {data.mode === "off" && (
          <div className="rounded-md bg-status-changed/10 p-3">
            <p className="text-sm font-medium text-status-changed">Host keys aren&apos;t checked</p>
            <p className="text-sm text-status-changed">
              Whoever answers at a host&apos;s address (a machine that took over a reused IP, someone on the
              network in between) gets the run&apos;s connection and everything it sends: files, templates and
              decrypted vault values.
              {canManage ? " Learn new hosts is a safe start." : " Ask a project admin to turn checking on."}
            </p>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <Label className="text-xs text-muted-foreground" htmlFor="host-key-mode">
            Mode
          </Label>
          {canManage ? (
            <Select value={data.mode} onValueChange={(value) => changeMode(value as HostKeyMode)}>
              <SelectTrigger id="host-key-mode" className="h-8 w-64 max-w-full" aria-label="Host key mode">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(MODE_LABELS) as HostKeyMode[]).map((mode) => (
                  <SelectItem key={mode} value={mode}>
                    {MODE_LABELS[mode]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <Badge variant={data.mode === "off" ? "changed" : "outline"}>{MODE_LABELS[data.mode]}</Badge>
          )}
        </div>
        {summary.hosts > 0 && (
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="text-muted-foreground">
              {summary.hosts} host{summary.hosts === 1 ? "" : "s"}:
            </span>
            {counts.map((status) => (
              <Badge key={status} variant={STATUS[status].variant}>
                {summary[status]} {STATUS[status].label}
              </Badge>
            ))}
          </div>
        )}
        {summary.hosts > 0 && (
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-sm font-medium">Hosts without a trusted key</span>
              <Input
                className="h-8 w-56 max-w-full"
                placeholder="Find a host"
                aria-label="Find a host"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
            {data.hosts.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {query ? "No matching host without a trusted key." : "Every host has a trusted key."}
              </p>
            ) : (
              <ul className="flex flex-col gap-1 text-sm">
                {data.hosts.map((host) => (
                  <li key={host.host} className="flex flex-wrap items-center gap-2">
                    <span className="wrap-anywhere">{host.host}</span>
                    {host.name && host.name !== host.host && (
                      <span className="font-mono text-xs text-muted-foreground wrap-anywhere">
                        {host.name}
                      </span>
                    )}
                    <Badge variant={STATUS[host.status].variant}>{STATUS[host.status].label}</Badge>
                    {host.reason && <span className="text-xs text-muted-foreground">{host.reason}</span>}
                  </li>
                ))}
              </ul>
            )}
            {data.total > data.hosts.length && (
              <p className="text-xs text-muted-foreground">
                Showing {data.hosts.length} of {data.total}; search to find the others.
              </p>
            )}
          </div>
        )}
        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium">Trusted keys</span>
          {data.keys.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No keys yet.
              {data.mode === "accept_new" && " Each host's key is learned on its first run."}
            </p>
          )}
          {data.keys.map((hostKey) => (
            <KeyRow
              key={hostKey.id}
              hostKey={hostKey}
              canManage={canManage}
              onRemove={(target) => {
                const next =
                  data.mode === "strict"
                    ? "its runs fail until you trust a new key"
                    : data.mode === "accept_new"
                      ? "its next run learns whatever key it is shown"
                      : "nothing changes until checking is on";
                if (window.confirm(`Remove the ${target.key_type} key of ${target.name}? Then ${next}.`)) {
                  act(() => api.removeHostKey(inventoryId, target.id));
                }
              }}
            />
          ))}
        </div>
      </CardContent>
      {pasting && (
        <PasteDialog inventoryId={inventoryId} open onClose={() => setPasting(false)} onSaved={load} />
      )}
    </Card>
  );
}
