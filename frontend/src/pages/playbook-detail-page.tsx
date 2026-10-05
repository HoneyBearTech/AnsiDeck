import { CircleAlert, TriangleAlert } from "lucide-react";
import * as React from "react";
import { useNavigate, useParams } from "react-router-dom";

import { CodeEditor, type CodeEditorHandle, type EditorDiagnostic } from "@/components/code-editor";
import { Button } from "@/components/ui/button";
import { FilePicker } from "@/components/ui/file-picker";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, type LintFinding, type LintJob, type PlaybookDetail } from "@/lib/api";

const POLL_MS = 1000;
const ACTIVE: LintJob["status"][] = ["queued", "running"];

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

/** What the check found, or where it is, in one sentence (announced as it changes). */
function summary(job: LintJob): string {
  switch (job.status) {
    case "queued":
      return `Waiting to check: ${job.wait_reason ?? "queued"}`;
    case "running":
      return "Checking with ansible-lint…";
    case "cancelled":
      return "Replaced by a newer check.";
    case "timed_out":
      return `The check timed out${job.error ? `: ${job.error}` : "."}`;
    case "failed":
      return `The check failed: ${job.error ?? "unknown error"}`;
    default: {
      if (job.total === 0) return "No problems found.";
      const errors = job.findings.filter((f) => f.level === "error").length;
      const warnings = job.findings.length - errors;
      const parts = [errors && plural(errors, "error"), warnings && plural(warnings, "warning")].filter(Boolean);
      return `${parts.join(", ")} found.`;
    }
  }
}

function FindingItem({ finding, onGoTo }: { finding: LintFinding; onGoTo: (finding: LintFinding) => void }) {
  const error = finding.level === "error";
  const Icon = error ? CircleAlert : TriangleAlert;
  const where = `${finding.in_target ? "" : `${finding.path}:`}${finding.line}${finding.column ? `:${finding.column}` : ""}`;
  return (
    <li className="flex flex-col gap-1 rounded-md border border-border p-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <span className={error ? "flex items-center gap-1 text-status-failed" : "flex items-center gap-1 text-status-changed"}>
          <Icon aria-hidden="true" className="size-4" />
          {error ? "Error" : "Warning"}
        </span>
        <span className="font-mono text-muted-foreground">{where}</span>
        <span>{finding.message}</span>
        {finding.url ? (
          <a href={finding.url} target="_blank" rel="noreferrer noopener" className="font-mono text-xs text-primary hover:underline">
            {finding.rule}
          </a>
        ) : (
          <span className="font-mono text-xs text-muted-foreground">{finding.rule}</span>
        )}
        {finding.in_target && (
          <Button variant="ghost" size="sm" className="h-7 px-2" onClick={() => onGoTo(finding)}>
            Go to line {finding.line}
          </Button>
        )}
      </div>
      {finding.details && (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer">Details</summary>
          <pre className="mt-1 overflow-x-auto whitespace-pre-wrap font-mono">{finding.details}</pre>
        </details>
      )}
    </li>
  );
}

function CheckResults({
  job,
  stale,
  onGoTo,
}: {
  job: LintJob;
  stale: boolean;
  onGoTo: (finding: LintFinding) => void;
}) {
  const done = job.status === "success";
  return (
    <section aria-labelledby="check-results-heading" className="flex flex-col gap-3 rounded-md border border-border bg-card p-4">
      <h2 id="check-results-heading" className="font-medium">
        Check results
      </h2>
      <p aria-live="polite" className={job.status === "failed" || job.status === "timed_out" ? "text-sm text-destructive" : "text-sm"}>
        {summary(job)}
      </p>
      {stale && done && (
        <p className="text-sm text-status-changed">The text has changed since this check: check again to update it.</p>
      )}
      {done && job.findings.length > 0 && (
        <ul className="flex flex-col gap-2">
          {job.findings.map((finding, index) => (
            <FindingItem
              // Findings have no id; their place in this result is stable.
              // oxlint-disable-next-line react/no-array-index-key -- a result's list never reorders
              key={`${index}-${finding.rule}`}
              finding={finding}
              onGoTo={onGoTo}
            />
          ))}
        </ul>
      )}
      {done && (
        <p className="text-xs text-muted-foreground">
          {job.ansible_lint_version ? `ansible-lint ${job.ansible_lint_version}` : "ansible-lint"} ·{" "}
          {job.repo_config ? "with the repository's ansible-lint config" : "default rules"}
          {job.commit && ` · at ${job.commit.slice(0, 8)}`}
          {job.truncated && ` · showing the first ${job.findings.length} of ${job.total}`}
          {job.external > 0 && ` · ${plural(job.external, "finding")} in installed collections not shown`}
          {job.scrubbed && " · a secret's value was removed from the findings"}
        </p>
      )}
    </section>
  );
}

export function PlaybookDetailPage() {
  const { can, canInProject } = useAuth();
  const [synced, setSynced] = React.useState<PlaybookDetail | null>(null);
  const [projectId, setProjectId] = React.useState<number | null>(null);
  const canWrite = can("content:write") && synced === null;
  const params = useParams<{ id: string }>();
  const navigate = useNavigate();
  const isNew = params.id === undefined;
  const playbookId = params.id ? Number(params.id) : null;
  const editor = React.useRef<CodeEditorHandle>(null);

  const [name, setName] = React.useState("");
  const [content, setContent] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [loading, setLoading] = React.useState(!isNew);
  const [check, setCheck] = React.useState<LintJob | null>(null);
  const [checkedContent, setCheckedContent] = React.useState<string | null>(null);
  const [checkError, setCheckError] = React.useState<string | null>(null);
  const [starting, setStarting] = React.useState(false);

  React.useEffect(() => {
    if (playbookId === null) return;
    api.getPlaybook(playbookId).then((playbook) => {
      setName(playbook.name);
      setContent(playbook.content);
      setProjectId(playbook.project_id);
      setSynced(playbook.source_id !== null ? playbook : null);
      setLoading(false);
    });
  }, [playbookId]);

  // Follows a queued or running check until it ends: each answer schedules the next poll.
  const checking = check !== null && ACTIVE.includes(check.status);
  React.useEffect(() => {
    if (check === null || !ACTIVE.includes(check.status)) return;
    let active = true;
    const timer = setTimeout(async () => {
      try {
        const latest = await api.getLintJob(check.id);
        if (active) setCheck((current) => (current?.id === latest.id ? latest : current));
      } catch (err) {
        if (active) setCheckError(err instanceof ApiError ? err.message : "Something went wrong");
      }
    }, POLL_MS);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [check]);

  const canCheck = projectId === null ? can("content:write") : canInProject(projectId, "content:write");

  async function handleFile(file: File) {
    const text = await file.text();
    setContent(text);
    if (!name) setName(file.name);
  }

  async function handleSave() {
    setError(null);
    setSaving(true);
    try {
      if (playbookId === null) {
        const created = await api.createPlaybook(name, content);
        navigate(`/playbooks/${created.id}`);
      } else {
        await api.updatePlaybook(playbookId, { name, content });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSaving(false);
    }
  }

  async function handleCheck() {
    setCheckError(null);
    setStarting(true);
    try {
      const job = synced
        ? await api.lintPlaybook(synced.id)
        : await api.lintContent(content, projectId ?? undefined);
      setCheck(job);
      setCheckedContent(synced ? null : content);
    } catch (err) {
      setCheckError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setStarting(false);
    }
  }

  const diagnostics = React.useMemo<EditorDiagnostic[]>(
    () =>
      check?.status === "success"
        ? check.findings
            .filter((f) => f.in_target)
            .map((f) => ({ line: f.line, column: f.column, level: f.level, message: `${f.message} (${f.rule})` }))
        : [],
    [check],
  );

  if (loading) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">
        {isNew ? "New Playbook" : canWrite ? "Edit Playbook" : "Playbook"}
      </h1>

      {synced && (
        <p className="rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
          Synced from the git source <span className="font-medium text-foreground">{synced.source_name}</span>{" "}
          (<span className="font-mono">{synced.repo_path}</span>
          {synced.commit && (
            <>
              {" "}
              at <span className="font-mono">{synced.commit.slice(0, 8)}</span>
            </>
          )}
          ). It is read-only here: change it in the repository.
          {synced.missing_at && " It has been removed from the repository, so it can no longer run."}
        </p>
      )}

      <div className="flex flex-col gap-2">
        <Label htmlFor="playbook-name">Name</Label>
        <Input
          id="playbook-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          readOnly={!canWrite}
        />
      </div>

      {canWrite && (
        <FilePicker id="playbook-file" label="Upload YAML file" accept=".yml,.yaml" onFile={handleFile} />
      )}

      <div className="flex flex-col gap-2">
        <Label id="playbook-content-label" onClick={() => editor.current?.focus()}>
          Content
        </Label>
        <CodeEditor
          ref={editor}
          labelledBy="playbook-content-label"
          value={content}
          onChange={setContent}
          readOnly={!canWrite}
          diagnostics={diagnostics}
          className="[&_.cm-editor]:min-h-96"
        />
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {(canWrite || canCheck) && (
        <div className="flex flex-wrap items-center gap-3">
          {canWrite && (
            <Button onClick={handleSave} disabled={saving || !name || !content}>
              {saving ? "Saving…" : "Save"}
            </Button>
          )}
          {canCheck && (
            <Button
              variant="outline"
              onClick={handleCheck}
              disabled={starting || (!synced && !content) || (synced?.missing_at ?? null) !== null}
            >
              {starting || checking ? "Checking…" : "Check"}
            </Button>
          )}
          {canCheck && (
            <p className="text-xs text-muted-foreground">
              Check runs ansible-lint on {synced ? "the playbook in its repository" : "the text above, saved or not"}.
            </p>
          )}
        </div>
      )}

      {checkError && <p className="text-sm text-destructive">{checkError}</p>}
      {check && (
        <CheckResults
          job={check}
          stale={checkedContent !== null && checkedContent !== content}
          onGoTo={(finding) => editor.current?.goTo(finding.line, finding.column)}
        />
      )}
    </div>
  );
}
