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

      {run.extra_vars && Object.keys(run.extra_vars).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Extra vars</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto rounded-md bg-muted p-4 font-mono text-sm">
              {JSON.stringify(run.extra_vars, null, 2)}
            </pre>
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
