import * as React from "react";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, type EgressExtra, type EgressHostStatus, type EgressSettings } from "@/lib/api";

const STATUS: Record<EgressHostStatus, { label: string; variant: BadgeProps["variant"] }> = {
  ok: { label: "allowed", variant: "ok" },
  indirect: { label: "through a jump host or proxy", variant: "outline" },
  local: { label: "local", variant: "skipped" },
  unknown: { label: "address unknown", variant: "failed" },
};

const HELP = {
  restricted:
    "Runs may reach only this inventory's hosts (on any port), the first jump host each one names, the extra " +
    "entries below, and DNS. Everything else is refused, and the run page lists what was. AnsiDeck's API and " +
    "cloud metadata stay blocked whatever is listed.",
  open: "Runs may reach any address except AnsiDeck's API and cloud metadata.",
};

function errorMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : "Something went wrong";
}

function portsText(ports: [number, number][] | null): string {
  return (ports ?? []).map(([lo, hi]) => (lo === hi ? `${lo}` : `${lo}-${hi}`)).join(",");
}

/** One extra entry per line: `target [ports] [# note]`. */
// oxlint-disable-next-line react/only-export-components -- tested on its own
export function extrasText(extras: EgressExtra[]): string {
  return extras
    .map((e) => [e.target, portsText(e.ports), e.note ? `# ${e.note}` : ""].filter(Boolean).join(" "))
    .join("\n");
}

// oxlint-disable-next-line react/only-export-components -- tested on its own
export function parseExtrasText(text: string): {
  entries: { target: string; ports: string | null; note: string | null }[];
  lines: number[];
} {
  const entries: { target: string; ports: string | null; note: string | null }[] = [];
  const lines: number[] = [];
  text.split("\n").forEach((raw, index) => {
    const [body = "", ...comment] = raw.split("#");
    const note = comment.join("#").trim() || null;
    const [target, ...rest] = body.trim().split(/\s+/).filter(Boolean);
    if (!target) return;
    entries.push({ target, ports: rest.join("") || null, note });
    lines.push(index + 1);
  });
  return { entries, lines };
}

function ExtrasEditor({
  inventoryId,
  extras,
  onSaved,
}: {
  inventoryId: number;
  extras: EgressExtra[];
  onSaved: () => void;
}) {
  const [text, setText] = React.useState(() => extrasText(extras));
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [saved, setSaved] = React.useState(false);
  const changed = text.trim() !== extrasText(extras).trim();

  async function save() {
    const { entries, lines } = parseExtrasText(text);
    setError(null);
    setSaved(false);
    setSaving(true);
    try {
      const result = await api.setEgressExtras(inventoryId, entries);
      setText(extrasText(result));
      setSaved(true);
      onSaved();
    } catch (err) {
      // The server numbers entries; blank lines don't count, so name the line instead.
      setError(
        errorMessage(err).replace(/^entry (\d+):/, (_, n: string) => `line ${lines[Number(n) - 1] ?? n}:`),
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor="egress-extras">Extra entries</Label>
      <Textarea
        id="egress-extras"
        className="min-h-24 font-mono text-sm"
        placeholder={"10.20.0.0/16 443\npypi.org 443  # packages\nbastion.example.com 22"}
        value={text}
        onChange={(event) => {
          setText(event.target.value);
          setSaved(false);
        }}
        aria-describedby="egress-extras-help"
      />
      <p id="egress-extras-help" className="text-xs text-muted-foreground">
        One per line: an address, a network (CIDR) or a host name, then ports like 443, 80,443 or 8000-8100
        (any port if none), then # and a note. For hosts a playbook reaches that aren&apos;t in the inventory:
        package mirrors, delegate_to targets, a ProxyCommand&apos;s proxy.
      </p>
      {error && <p className="text-sm text-destructive">{error}</p>}
      {saved && <output className="text-sm text-status-ok">Saved.</output>}
      <Button size="sm" className="self-start" disabled={saving || !changed} onClick={() => void save()}>
        {saving ? "Saving…" : "Save entries"}
      </Button>
    </div>
  );
}

export function EgressPanel({
  inventoryId,
  projectId,
  onChanged,
}: {
  inventoryId: number;
  projectId: number;
  onChanged?: (restricted: boolean) => void;
}) {
  const { canInProject } = useAuth();
  const canManage = canInProject(projectId, "sources:manage");
  const [data, setData] = React.useState<EgressSettings | null>(null);
  const [query, setQuery] = React.useState("");
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const error = actionError ?? loadError;

  const load = React.useCallback(() => {
    api
      .getEgress(inventoryId, query)
      .then((result) => {
        setData(result);
        setLoadError(null);
      })
      .catch((err) => setLoadError(errorMessage(err)));
  }, [inventoryId, query]);

  React.useEffect(() => {
    load();
  }, [load]);

  async function changeMode(restricted: boolean) {
    if (!data || restricted === data.restricted) return;
    const { unknown } = data.summary;
    if (
      restricted &&
      unknown > 0 &&
      !window.confirm(
        `${unknown} host${unknown === 1 ? "'s address isn't" : "s' addresses aren't"} known before a run: ` +
          "its runs will be refused until that changes. Restrict anyway?",
      )
    ) {
      return;
    }
    if (!restricted && !window.confirm("Let this inventory's runs reach any address again?")) return;
    setActionError(null);
    try {
      await api.setEgressMode(inventoryId, restricted);
      onChanged?.(restricted);
    } catch (err) {
      setActionError(errorMessage(err));
    }
    load();
  }

  if (!data) {
    return error ? <p className="text-sm text-destructive">{error}</p> : null;
  }
  const { summary } = data;
  const counts = (Object.keys(STATUS) as EgressHostStatus[]).filter((status) => summary[status] > 0);

  return (
    <Card id="network-egress">
      <CardHeader className="flex flex-col gap-1">
        <CardTitle>Network</CardTitle>
        <p className="text-sm text-muted-foreground">{data.restricted ? HELP.restricted : HELP.open}</p>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex flex-wrap items-center gap-2">
          <Label className="text-xs text-muted-foreground" htmlFor="egress-mode">
            Runs may reach
          </Label>
          {canManage ? (
            <Select
              value={data.restricted ? "restricted" : "open"}
              onValueChange={(value) => void changeMode(value === "restricted")}
            >
              <SelectTrigger id="egress-mode" className="h-8 w-64 max-w-full" aria-label="Network access">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="open">Any address</SelectItem>
                <SelectItem value="restricted">Only its hosts</SelectItem>
              </SelectContent>
            </Select>
          ) : (
            <Badge variant="outline">{data.restricted ? "Only its hosts" : "Any address"}</Badge>
          )}
        </div>
        {data.restricted && summary.unknown > 0 && (
          <div className="rounded-md bg-status-failed/10 p-3 text-sm text-status-failed">
            {summary.unknown} host{summary.unknown === 1 ? "'s address isn't" : "s' addresses aren't"} known
            before a run (set by a template, or a connection AnsiDeck can&apos;t read), so its runs are
            refused.
          </div>
        )}
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
        {data.warnings.length > 0 && (
          <ul className="flex list-disc flex-col gap-1 pl-5 text-xs text-muted-foreground">
            {data.warnings.map((warning) => (
              <li key={warning} className="wrap-anywhere">
                {warning}
              </li>
            ))}
          </ul>
        )}
        {summary.hosts > 0 && (
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-sm font-medium">Where its hosts connect</span>
              <Input
                className="h-8 w-56 max-w-full"
                placeholder="Find a host"
                aria-label="Find a host by name or address"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
            {data.hosts.length === 0 ? (
              <p className="text-sm text-muted-foreground">No matching host.</p>
            ) : (
              <ul className="flex flex-col gap-1 text-sm">
                {data.hosts.map((host) => (
                  <li key={host.host} className="flex flex-wrap items-center gap-2">
                    <span className="wrap-anywhere">{host.host}</span>
                    {host.address && host.address !== host.host && (
                      <span className="font-mono text-xs text-muted-foreground wrap-anywhere">
                        {host.address}
                      </span>
                    )}
                    {host.jump_host && (
                      <span className="text-xs text-muted-foreground wrap-anywhere">
                        via {host.jump_host}
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
        {canManage ? (
          <ExtrasEditor inventoryId={inventoryId} extras={data.extras} onSaved={load} />
        ) : (
          data.extras.length > 0 && (
            <div className="flex flex-col gap-1">
              <span className="text-sm font-medium">Extra entries</span>
              <ul className="flex flex-col gap-1 font-mono text-sm">
                {data.extras.map((extra) => (
                  <li key={`${extra.target} ${portsText(extra.ports)}`} className="wrap-anywhere">
                    {extra.target}
                    {extra.ports ? ` ${portsText(extra.ports)}` : " (any port)"}
                    {extra.note && <span className="text-muted-foreground"> # {extra.note}</span>}
                  </li>
                ))}
              </ul>
            </div>
          )
        )}
      </CardContent>
    </Card>
  );
}
