import * as React from "react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { api, type PlaybookSummary } from "@/lib/api";

export function PlaybooksPage() {
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
        <Button asChild>
          <Link to="/playbooks/new">New Playbook</Link>
        </Button>
      </div>

      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {!loading && playbooks.length === 0 && (
        <p className="text-sm text-muted-foreground">No playbooks yet.</p>
      )}

      <div className="flex flex-col gap-2">
        {playbooks.map((playbook) => (
          <Card key={playbook.id}>
            <CardContent className="flex items-center justify-between p-4">
              <Link to={`/playbooks/${playbook.id}`} className="flex flex-col gap-1">
                <span className="font-medium">{playbook.name}</span>
                <span className="text-xs text-muted-foreground">
                  Updated {new Date(playbook.updated_at).toLocaleString()}
                </span>
              </Link>
              <div className="flex gap-2">
                <Button asChild size="sm">
                  <Link to="/runs/new">Run</Link>
                </Button>
                <Button variant="outline" size="sm" onClick={() => handleDelete(playbook.id)}>
                  Delete
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
