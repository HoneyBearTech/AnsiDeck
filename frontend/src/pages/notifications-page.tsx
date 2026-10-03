import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
  type ChannelKind,
  type ChannelUpdate,
  type NotificationCatalog,
  type NotificationChannel,
  type NotificationDelivery,
} from "@/lib/api";

const KIND_LABELS: Record<ChannelKind, string> = {
  discord: "Discord",
  slack: "Slack",
  teams: "Microsoft Teams",
  webhook: "Webhook",
  email: "Email",
  pushbullet: "Pushbullet",
  pushover: "Pushover",
};

const URL_HINTS: Partial<Record<ChannelKind, string>> = {
  discord: "https://discord.com/api/webhooks/…",
  slack: "https://hooks.slack.com/services/…",
  teams: "A Teams Workflows webhook URL (“When a Teams webhook request is received”)",
  webhook: "https://example.com/ansideck-hook",
};

function errorMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : "Something went wrong";
}

function usesUrl(kind: ChannelKind): boolean {
  return kind === "discord" || kind === "slack" || kind === "teams" || kind === "webhook";
}

function deliveryVariant(status: string): "ok" | "failed" | "changed" | "skipped" {
  if (status === "sent") return "ok";
  if (status === "failed") return "failed";
  if (status === "pending" || status === "sending") return "changed";
  return "skipped";
}

function ChannelDialog({
  open,
  onOpenChange,
  projectId,
  catalog,
  channel,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: number | null;
  catalog: NotificationCatalog;
  channel?: NotificationChannel;
  onSaved: () => void;
}) {
  const editing = !!channel;
  const [name, setName] = React.useState("");
  const [kind, setKind] = React.useState<ChannelKind>("discord");
  const [url, setUrl] = React.useState("");
  const [secret, setSecret] = React.useState("");
  const [removeSecret, setRemoveSecret] = React.useState(false);
  const [token, setToken] = React.useState("");
  const [userKey, setUserKey] = React.useState("");
  const [recipients, setRecipients] = React.useState("");
  const [events, setEvents] = React.useState<string[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  const available = catalog.events.filter((e) => projectId === null || e.project);

  React.useEffect(() => {
    if (!open) return;
    setName(channel?.name ?? "");
    setKind(channel?.kind ?? "discord");
    setUrl("");
    setSecret("");
    setRemoveSecret(false);
    setToken("");
    setUserKey("");
    setRecipients(channel?.recipients?.join("\n") ?? "");
    setEvents(channel?.events ?? available.map((e) => e.name));
    setError(null);
    // available is derived from props that don't change while the dialog is open
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, channel]);

  function toggleEvent(name: string, on: boolean) {
    setEvents((current) => (on ? [...current, name] : current.filter((e) => e !== name)));
  }

  function secrets(): ChannelUpdate {
    const out: ChannelUpdate = {};
    if (usesUrl(kind) && url.trim()) out.url = url.trim();
    if (kind === "webhook") {
      if (removeSecret) out.secret = "";
      else if (secret) out.secret = secret;
    }
    if ((kind === "pushbullet" || kind === "pushover") && token.trim()) out.token = token.trim();
    if (kind === "pushover" && userKey.trim()) out.user_key = userKey.trim();
    if (kind === "email") {
      const list = recipients
        .split(/[\n,]/)
        .map((r) => r.trim())
        .filter(Boolean);
      if (!editing || list.join() !== (channel?.recipients ?? []).join()) out.recipients = list;
    }
    return out;
  }

  async function handleSave() {
    setError(null);
    setSaving(true);
    try {
      if (channel) {
        await api.updateChannel(projectId, channel.id, { name: name.trim(), events, ...secrets() });
      } else {
        await api.createChannel(projectId, { name: name.trim(), kind, events, ...secrets() });
      }
      onOpenChange(false);
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  const keep = editing ? "Leave empty to keep the current one" : undefined;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{editing ? `Edit ${channel.name}` : "New channel"}</DialogTitle>
          <DialogDescription>
            {projectId === null
              ? "A global channel: ops and security events, and run events from every project."
              : "Run events from this project."}{" "}
            URLs and tokens are stored encrypted and never shown again.
          </DialogDescription>
        </DialogHeader>
        <div className="-mx-1 flex max-h-[65vh] flex-col gap-4 overflow-y-auto px-1">
          <div className="flex flex-col gap-2">
            <Label htmlFor="channel-name">Name</Label>
            <Input id="channel-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          {!editing && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="channel-kind">Send to</Label>
              <Select value={kind} onValueChange={(value) => setKind(value as ChannelKind)}>
                <SelectTrigger id="channel-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {catalog.kinds.map((k) => (
                    <SelectItem key={k} value={k} disabled={k === "email" && !catalog.email_available}>
                      {KIND_LABELS[k]}
                      {k === "email" && !catalog.email_available ? " (needs SMTP_HOST)" : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {usesUrl(kind) && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="channel-url">Webhook URL</Label>
              <Input
                id="channel-url"
                type="password"
                autoComplete="off"
                value={url}
                placeholder={keep ?? URL_HINTS[kind]}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>
          )}
          {kind === "webhook" && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="channel-secret">Signing secret (optional)</Label>
              <Input
                id="channel-secret"
                type="password"
                autoComplete="off"
                value={secret}
                disabled={removeSecret}
                placeholder={
                  channel?.has_secret ? "Leave empty to keep the current one" : "Signs X-AnsiDeck-Signature"
                }
                onChange={(e) => setSecret(e.target.value)}
              />
              {channel?.has_secret && (
                <label className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Checkbox checked={removeSecret} onCheckedChange={(v) => setRemoveSecret(v === true)} />
                  Remove the signing secret
                </label>
              )}
            </div>
          )}
          {(kind === "pushbullet" || kind === "pushover") && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="channel-token">
                {kind === "pushbullet" ? "Access token" : "Application API token"}
              </Label>
              <Input
                id="channel-token"
                type="password"
                autoComplete="off"
                value={token}
                placeholder={keep}
                onChange={(e) => setToken(e.target.value)}
              />
            </div>
          )}
          {kind === "pushover" && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="channel-user">User or group key</Label>
              <Input
                id="channel-user"
                type="password"
                autoComplete="off"
                value={userKey}
                placeholder={keep}
                onChange={(e) => setUserKey(e.target.value)}
              />
            </div>
          )}
          {kind === "email" && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="channel-recipients">Recipients (one per line)</Label>
              <Textarea
                id="channel-recipients"
                className="min-h-20"
                value={recipients}
                onChange={(e) => setRecipients(e.target.value)}
              />
            </div>
          )}
          <div className="flex flex-col gap-2">
            <Label>Events</Label>
            {[...new Set(available.map((e) => e.group))].map((group) => (
              <fieldset key={group} className="flex flex-col gap-2">
                <legend className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  {group}
                </legend>
                {available
                  .filter((e) => e.group === group)
                  .map((event) => (
                    <label key={event.name} className="flex items-start gap-2 text-sm">
                      <Checkbox
                        className="mt-0.5"
                        checked={events.includes(event.name)}
                        onCheckedChange={(v) => toggleEvent(event.name, v === true)}
                      />
                      <span>
                        {event.label}
                        <span className="block text-muted-foreground">{event.description}</span>
                      </span>
                    </label>
                  ))}
              </fieldset>
            ))}
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleSave} disabled={saving || !name.trim() || events.length === 0}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function DeliveryLog({ projectId, channelId }: { projectId: number | null; channelId: number }) {
  const [deliveries, setDeliveries] = React.useState<NotificationDelivery[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    api
      .listDeliveries(projectId, channelId)
      .then(setDeliveries)
      .catch((err) => setError(errorMessage(err)));
  }, [projectId, channelId]);

  if (error) return <p className="text-sm text-destructive">{error}</p>;
  if (deliveries === null) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (deliveries.length === 0) return <p className="text-sm text-muted-foreground">Nothing sent yet.</p>;
  return (
    <ul className="flex flex-col gap-1 text-sm">
      {deliveries.map((d) => (
        <li key={d.id} className="flex flex-wrap items-center gap-2">
          <Badge variant={deliveryVariant(d.status)}>{d.status}</Badge>
          <span>{d.title}</span>
          <span className="text-muted-foreground">
            {new Date(d.created_at).toLocaleString()}
            {d.attempts > 1 && ` · ${d.attempts} attempts`}
            {d.last_error && ` · ${d.last_error}`}
            {d.next_attempt_at && ` · next try ${new Date(d.next_attempt_at).toLocaleTimeString()}`}
          </span>
        </li>
      ))}
    </ul>
  );
}

function ChannelCard({
  channel,
  projectId,
  catalog,
  onChanged,
}: {
  channel: NotificationChannel;
  projectId: number | null;
  catalog: NotificationCatalog;
  onChanged: () => void;
}) {
  const [editing, setEditing] = React.useState(false);
  const [showLog, setShowLog] = React.useState(false);
  const [message, setMessage] = React.useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = React.useState(false);
  const labels = Object.fromEntries(catalog.events.map((e) => [e.name, e.label]));

  async function act(action: () => Promise<unknown>) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      onChanged();
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  }

  async function handleTest() {
    setBusy(true);
    setMessage(null);
    try {
      const result = await api.testChannel(projectId, channel.id);
      setMessage(
        result.ok
          ? { ok: true, text: "Test message sent." }
          : { ok: false, text: `Test failed: ${result.error ?? "unknown error"}` },
      );
      onChanged();
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  }

  const last = channel.last_delivery;
  return (
    <Card>
      <CardContent className="flex flex-col gap-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <Switch
              className="data-[state=checked]:bg-primary"
              checked={channel.enabled}
              disabled={busy}
              aria-label={channel.enabled ? "Turn off" : "Turn on"}
              onCheckedChange={(enabled) => act(() => api.updateChannel(projectId, channel.id, { enabled }))}
            />
            <span className="font-medium">{channel.name}</span>
            <Badge variant="outline">{KIND_LABELS[channel.kind]}</Badge>
            <span className="font-mono text-xs text-muted-foreground">{channel.target}</span>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={busy} onClick={handleTest}>
              Send test
            </Button>
            <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
              Edit
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={() => {
                if (window.confirm(`Delete the channel "${channel.name}"? Its delivery history goes too.`)) {
                  act(() => api.deleteChannel(projectId, channel.id));
                }
              }}
            >
              Delete
            </Button>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
          {channel.events.map((e) => (
            <Badge key={e} variant="default">
              {labels[e] ?? e}
            </Badge>
          ))}
          {last ? (
            <span>
              · last: <Badge variant={deliveryVariant(last.status)}>{last.status}</Badge>{" "}
              {new Date(last.created_at).toLocaleString()}
              {last.error && ` (${last.error})`}
            </span>
          ) : (
            <span>· nothing sent yet</span>
          )}
          <button
            type="button"
            className="text-primary hover:underline"
            onClick={() => setShowLog((v) => !v)}
          >
            {showLog ? "Hide history" : "History"}
          </button>
        </div>
        {message && (
          <p className={message.ok ? "text-sm text-status-ok" : "text-sm text-destructive"}>{message.text}</p>
        )}
        {showLog && <DeliveryLog projectId={projectId} channelId={channel.id} />}
      </CardContent>
      <ChannelDialog
        open={editing}
        onOpenChange={setEditing}
        projectId={projectId}
        catalog={catalog}
        channel={channel}
        onSaved={onChanged}
      />
    </Card>
  );
}

function ChannelSection({
  title,
  description,
  projectId,
  catalog,
}: {
  title: string;
  description: string;
  projectId: number | null;
  catalog: NotificationCatalog;
}) {
  const [channels, setChannels] = React.useState<NotificationChannel[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [creating, setCreating] = React.useState(false);

  const refresh = React.useCallback(() => {
    api
      .listChannels(projectId)
      .then((list) => {
        setChannels(list);
        setError(null);
      })
      .catch((err) => setError(errorMessage(err)));
  }, [projectId]);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold">{title}</h2>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
        <Button onClick={() => setCreating(true)}>New channel</Button>
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      {channels === null && !error && <p className="text-sm text-muted-foreground">Loading…</p>}
      {channels?.length === 0 && <p className="text-sm text-muted-foreground">No channels yet.</p>}
      {channels?.map((channel) => (
        <ChannelCard
          key={channel.id}
          channel={channel}
          projectId={projectId}
          catalog={catalog}
          onChanged={refresh}
        />
      ))}
      <ChannelDialog
        open={creating}
        onOpenChange={setCreating}
        projectId={projectId}
        catalog={catalog}
        onSaved={refresh}
      />
    </section>
  );
}

export function NotificationsPage() {
  const { can, canInProject, activeProject } = useAuth();
  const [catalog, setCatalog] = React.useState<NotificationCatalog | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    api
      .notificationCatalog()
      .then(setCatalog)
      .catch((err) => setError(errorMessage(err)));
  }, []);

  const global = can("notifications:global");
  const project =
    activeProject && canInProject(activeProject.id, "notifications:manage") ? activeProject : null;

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-xl font-semibold">Notifications</h1>
        <p className="text-sm text-muted-foreground">
          Send events to Discord, Slack, Microsoft Teams, a webhook, email, Pushbullet or Pushover. Messages
          carry run details (names, status, failed task and host names) but never secrets or task output.
        </p>
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      {catalog && global && (
        <ChannelSection
          title="Global channels"
          description="For global admins: run events from every project (and ops and security events as they are added)."
          projectId={null}
          catalog={catalog}
        />
      )}
      {catalog && project && (
        <ChannelSection
          title={`${project.name} channels`}
          description="Run events from this project, managed by its admins."
          projectId={project.id}
          catalog={catalog}
        />
      )}
      {catalog && !project && (
        <p className="text-sm text-muted-foreground">
          Pick a project in the switcher at the top to manage that project's own channels.
        </p>
      )}
    </div>
  );
}
