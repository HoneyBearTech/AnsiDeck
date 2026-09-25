import * as React from "react";
import { useParams } from "react-router-dom";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LiveLogViewer } from "@/components/live-log-viewer";
import { api, type Run } from "@/lib/api";

const STATUS_VARIANT: Record<Run["status"], BadgeProps["variant"]> = {
  success: "ok",
  failed: "failed",
  running: "changed",
  queued: "skipped",
};

// From ansible's PLAY RECAP; zero counts are left out.
const HOST_OUTCOMES: { key: keyof Run; label: string; variant: BadgeProps["variant"] }[] = [
  { key: "hosts_ok", label: "ok", variant: "ok" },
  { key: "hosts_changed", label: "changed", variant: "changed" },
  { key: "hosts_failed", label: "failed", variant: "failed" },
  { key: "hosts_unreachable", label: "unreachable", variant: "failed" },
];

function seconds(from: string | null, to: string | null): string | null {
  if (!from || !to) return null;
  const s = (new Date(to).getTime() - new Date(from).getTime()) / 1000;
  return s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)} min ${Math.floor(s % 60)} s`;
}

function RunSummary({ run }: { run: Run }) {
  const waited = seconds(run.queued_at, run.started_at);
  const ran = seconds(run.started_at, run.finished_at);
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-muted-foreground">
      {run.hosts_total !== null && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span>
            {run.hosts_total} {run.hosts_total === 1 ? "host" : "hosts"}
          </span>
          {HOST_OUTCOMES.map(({ key, label, variant }) =>
            run[key] ? (
              <Badge key={key} variant={variant}>
                {run[key] as number} {label}
              </Badge>
            ) : null,
          )}
        </div>
      )}
      {waited && <span>waited {waited}</span>}
      {ran && <span>ran {ran}</span>}
      {run.return_code !== null && <span>exit code {run.return_code}</span>}
    </div>
  );
}

export function RunDetailPage() {
  const params = useParams<{ id: string }>();
  const runId = Number(params.id);
  const [run, setRun] = React.useState<Run | null>(null);

  React.useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;

    async function poll() {
      const latest = await api.getRun(runId);
      if (!active) return;
      setRun(latest);
      if (latest.status === "queued" || latest.status === "running") {
        timer = setTimeout(poll, 1000);
      }
    }
    poll();

    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [runId]);

  if (!run) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">
            {run.playbook_name} → {run.inventory_name}
            {run.group_name ? ` / ${run.group_name}` : ""}
          </h1>
          <p className="text-sm text-muted-foreground">
            Triggered by {run.triggered_by} · credential {run.credential_name}
            {run.vault_password_name && ` · vault: ${run.vault_password_name}`}
            {run.become && " · become"}
            {run.check_mode && " · check"}
            {run.diff_mode && " · diff"}
            {run.limit && ` · limit: ${run.limit}`}
          </p>
        </div>
        <Badge variant={STATUS_VARIANT[run.status]}>{run.status}</Badge>
      </div>

      <RunSummary run={run} />

      {run.extra_vars && Object.keys(run.extra_vars).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Extra vars</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto rounded-md bg-muted p-4 font-mono text-sm">
              {JSON.stringify(run.extra_vars, null, 2)}
            </pre>
            <p className="mt-2 text-xs text-muted-foreground">
              Values whose names look secret (password, token, key, …) are masked here and in
              the run output.
            </p>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Live output</CardTitle>
        </CardHeader>
        <CardContent>
          <LiveLogViewer runId={runId} />
        </CardContent>
      </Card>
    </div>
  );
}
