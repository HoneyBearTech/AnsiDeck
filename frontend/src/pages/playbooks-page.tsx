import * as React from "react";
import { Link } from "react-router-dom";

import { GitSourcesPanel } from "@/components/git-sources-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/context/auth-context";
import { api, type PlaybookSummary } from "@/lib/api";
import { shortSha } from "@/lib/git";

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

  async function handleDelete(id: number) {
    await api.deletePlaybook(id);
    refresh();
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Playbooks</h1>
        {canWrite && (
          <Button asChild>
            <Link to="/playbooks/new">New Playbook</Link>
          </Button>
        )}
      </div>

      {activeProject ? (
        <GitSourcesPanel projectId={activeProject.id} onSynced={refresh} />
      ) : (
        <p className="text-sm text-muted-foreground">
          Pick a project in the switcher at the top to see and manage its git sources.
        </p>
      )}

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
                <Link to={`/playbooks/${playbook.id}`} className="flex min-w-0 flex-col gap-1">
                  <span className="flex flex-wrap items-center gap-2 font-medium">
                    {playbook.name}
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
                <div className="flex gap-2">
                  {canRun && !missing && (
                    <Button asChild size="sm">
                      <Link to="/runs/new">Run</Link>
                    </Button>
                  )}
                  {canWrite && (!synced || missing) && (
                    <Button variant="outline" size="sm" onClick={() => handleDelete(playbook.id)}>
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
