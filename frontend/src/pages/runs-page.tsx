import * as React from "react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/page-header";
import { RunRow } from "@/components/run-row";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/context/auth-context";
import { api, type Run } from "@/lib/api";

export function RunsPage() {
  const { can } = useAuth();
  const [runs, setRuns] = React.useState<Run[]>([]);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    api.listRuns().then((r) => {
      setRuns(r);
      setLoading(false);
    });
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Runs"
        description="Every run, newest first, with its target, options and outcome."
        actions={
          can("runs:trigger") && (
            <Button asChild>
              <Link to="/runs/new">New run</Link>
            </Button>
          )
        }
      />

      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {!loading && runs.length === 0 && <p className="text-sm text-muted-foreground">No runs yet.</p>}

      <div className="flex flex-col gap-2">
        {runs.map((run) => (
          <RunRow key={run.id} run={run} />
        ))}
      </div>
    </div>
  );
}
