import { ChevronRight } from "lucide-react";
import * as React from "react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/page-header";
import { ProjectBadge } from "@/components/project-badge";
import { GitSourcesPanel } from "@/components/git-sources-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/context/auth-context";
import { api, type PlaybookSummary } from "@/lib/api";
import { shortSha } from "@/lib/git";
import { useConfirmedAction } from "@/lib/use-confirmed-action";

export function PlaybooksPage() {
  const { can, activeProject } = useAuth();
  const canWrite = can("content:write");
  const canRun = can("runs:trigger");
  const [playbooks, setPlaybooks] = React.useState<PlaybookSummary[]>([]);
  const [loading, setLoading] = React.useState(true);

  const refresh = React.useCallback(() => {
    api.listPlaybooks().then((p) => {
      setPlaybooks(p);
      setLoading(false);
    });
  }, []);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  const deletion = useConfirmedAction(refresh);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Playbooks"
        description="What runs do: written here, imported from a file, or synced from git."
        actions={
          canWrite && (
            <Button asChild>
              <Link to="/playbooks/new">New playbook</Link>
            </Button>
          )
        }
      />

      {activeProject ? (
        <GitSourcesPanel projectId={activeProject.id} onSynced={refresh} />
      ) : (
        <p className="text-sm text-muted-foreground">
          Git sources belong to a project: pick one in the project switcher to see and manage them.
        </p>
      )}

      {deletion.error && <p className="text-sm text-destructive">{deletion.error}</p>}
      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {!loading && playbooks.length === 0 && (
        <p className="text-sm text-muted-foreground">No playbooks yet.</p>
      )}

      <div className="flex flex-col gap-2">
        {playbooks.map((playbook) => {
          const synced = playbook.source_id !== null;
          const missing = playbook.missing_at !== null;
          return (
            <Card key={playbook.id} className={missing ? "opacity-60" : undefined}>
              <CardContent className="flex items-center justify-between gap-4 p-4">
                <Link to={`/playbooks/${playbook.id}`} className="group flex min-w-0 flex-col gap-1">
                  <span className="flex flex-wrap items-center gap-2 font-medium">
                    <span className="flex items-center gap-1 break-all group-hover:text-primary">
                      {playbook.name}
                      <ChevronRight aria-hidden="true" className="size-4 shrink-0 text-muted-foreground group-hover:text-primary" />
                    </span>
                    <ProjectBadge projectId={playbook.project_id} />
                    {synced && (
                      <Badge variant="outline" title={`Synced from ${playbook.source_name}`}>
                        git · {playbook.source_name}
                        {playbook.commit && ` @ ${shortSha(playbook.commit)}`}
                      </Badge>
                    )}
                    {missing && <Badge variant="failed">removed upstream</Badge>}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    Updated {new Date(playbook.updated_at).toLocaleString()}
                  </span>
                </Link>
                <div className="flex shrink-0 gap-2">
                  {canRun && !missing && (
                    <Button asChild size="sm">
                      <Link to={`/runs/new?playbook=${playbook.id}`} aria-label={`Run ${playbook.name}`}>
                        Run
                      </Link>
                    </Button>
                  )}
                  {canWrite && (!synced || missing) && (
                    <Button variant="destructive-outline" size="sm" onClick={() =>
                        deletion.run(
                          `Delete the playbook "${playbook.name}"? This can't be undone; its run history stays.`,
                          () => api.deletePlaybook(playbook.id),
                        )
                      }>
                      Delete
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
