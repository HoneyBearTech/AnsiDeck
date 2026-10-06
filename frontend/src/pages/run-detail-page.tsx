import * as React from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LiveLogViewer } from "@/components/live-log-viewer";
import { PageHeader } from "@/components/page-header";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, type Run } from "@/lib/api";
import { deletedItems, describeDeleted, formatDuration, STATUS_VARIANT } from "@/lib/runs";


// From ansible's PLAY RECAP; zero counts are left out.
const HOST_OUTCOMES: { key: keyof Run; label: string; variant: BadgeProps["variant"] }[] = [
  { key: "hosts_ok", label: "ok", variant: "ok" },
  { key: "hosts_changed", label: "changed", variant: "changed" },
  { key: "hosts_failed", label: "failed", variant: "failed" },
  { key: "hosts_unreachable", label: "unreachable", variant: "failed" },
];

// What the badge alone doesn't say: what a queued run waits for (a worker, the run ahead of it on the
// inventory, ...), that it is being cancelled, or why it ended the way it did (worker lost, timed out, ...).
function StatusNote({ run }: { run: Run }) {
  let note: string | null = run.status_reason;
  if (run.status === "queued") note = run.waiting_reason ?? "Waiting for a worker…";
  else if (run.status === "running" && run.cancel_requested_at) note = "Cancelling…";
  if (!note) return null;
  const bad = run.status === "failed" || run.status === "timed_out";
  return <p className={bad ? "text-sm text-destructive" : "text-sm text-muted-foreground"}>{note}</p>;
}

function RunSummary({ run }: { run: Run }) {
  const waited = formatDuration(run.queued_at, run.started_at);
  const ran = formatDuration(run.started_at, run.finished_at);
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

function CancelButton({ run, onCancelled }: { run: Run; onCancelled: (run: Run) => void }) {
  const { canInProject } = useAuth();
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const active = run.status === "queued" || run.status === "running";
  if (!active || !canInProject(run.project_id, "runs:trigger")) return null;

  async function handleCancel() {
    const what =
      run.status === "queued"
        ? "It hasn't started yet and won't run."
        : "Ansible is stopped where it is; tasks already done on the hosts are not undone.";
    if (!window.confirm(`Cancel run #${run.id}? ${what}`)) return;
    setError(null);
    setBusy(true);
    try {
      onCancelled(await api.cancelRun(run.id));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        variant="destructive"
        size="sm"
        onClick={handleCancel}
        disabled={busy || !!run.cancel_requested_at}
      >
        {busy || run.cancel_requested_at ? "Cancelling…" : "Cancel run"}
      </Button>
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}

/** "Run again" starts the same run at once (after a confirmation); "Edit and run" opens the form with
 * its settings filled in. */
function RunAgain({ run }: { run: Run }) {
  const { canInProject } = useAuth();
  const navigate = useNavigate();
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  if (!canInProject(run.project_id, "runs:trigger")) return null;
  const missing = deletedItems(run);

  async function handleRerun() {
    const target = `${run.playbook_name} on ${run.inventory_name}${run.group_name ? ` / ${run.group_name}` : ""}`;
    const root = run.become ? " It runs as root (become)." : "";
    const question =
      `Run ${target} again, with the same credential, options and extra vars?${root} ` +
      "The playbook and inventory are used as they are now.";
    if (!window.confirm(question)) return;
    setError(null);
    setBusy(true);
    try {
      const next = await api.rerun(run.id);
      navigate(`/runs/${next.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={handleRerun} disabled={busy || missing.length > 0}>
          {busy ? "Starting…" : "Run again"}
        </Button>
        <Button variant="outline" size="sm" asChild>
          <Link to={`/runs/new?from_run=${run.id}`}>Edit and run</Link>
        </Button>
      </div>
      {missing.length > 0 && (
        <p className="text-xs text-muted-foreground">Can&apos;t run again as it was: {describeDeleted(missing)}.</p>
      )}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}

function DownloadLog({ run }: { run: Run }) {
  if (run.status === "queued") return null;
  const link = "text-sm text-primary hover:underline";
  return (
    <p className="flex items-center gap-2 text-sm text-muted-foreground">
      Download:
      <a href={api.runLogUrl(run.id, "text")} download className={link}>
        text
      </a>
      ·
      <a href={api.runLogUrl(run.id, "jsonl")} download className={link}>
        JSON lines
      </a>
    </p>
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
  const live = run.status === "queued" || run.status === "running";

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        back={{ to: "/runs", label: "Runs" }}
        title={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="min-w-0 wrap-anywhere">
              <span className="mr-2 font-mono text-base text-muted-foreground">#{run.id}</span>
              {run.playbook_name} →&nbsp;{run.inventory_name}
              {run.group_name && <> /&nbsp;{run.group_name}</>}
            </span>
            <Badge variant={STATUS_VARIANT[run.status]}>{run.status.replace("_", " ")}</Badge>
          </span>
        }
        actions={
          <>
            <RunAgain run={run} />
            <CancelButton run={run} onCancelled={setRun} />
          </>
        }
      />
      <div className="-mt-4 flex flex-col gap-1">
          <p className="text-sm text-muted-foreground">
            Triggered by {run.triggered_by} · credential {run.credential_name}
            {run.vault_password_name && ` · vault: ${run.vault_password_name}`}
            {run.become && " · become"}
            {run.check_mode && " · check"}
            {run.diff_mode && " · diff"}
            {run.limit && ` · limit: ${run.limit}`}
          </p>
          {run.git_commit && (
            <p className="text-sm text-muted-foreground">
              From git source {run.git_source_name} · <span className="font-mono">{run.playbook_path}</span>{" "}
              at{" "}
              {run.commit_url ? (
                <a
                  href={run.commit_url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="font-mono text-primary hover:underline"
                >
                  {run.git_commit.slice(0, 8)}
                </a>
              ) : (
                <span className="font-mono text-foreground">{run.git_commit.slice(0, 8)}</span>
              )}
            </p>
          )}
          <StatusNote run={run} />
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
              Values whose names look secret (password, token, key, …) are masked here and in the run output.
            </p>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <CardTitle>{live ? "Live output" : "Output"}</CardTitle>
          <DownloadLog run={run} />
        </CardHeader>
        <CardContent>
          <LiveLogViewer key={runId} runId={runId} follow={live} />
        </CardContent>
      </Card>
    </div>
  );
}
