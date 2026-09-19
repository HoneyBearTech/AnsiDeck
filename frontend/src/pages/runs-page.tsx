import * as React from "react";
import { Link } from "react-router-dom";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/context/auth-context";
import { api, type Run } from "@/lib/api";

const STATUS_VARIANT: Record<Run["status"], BadgeProps["variant"]> = {
  success: "ok",
  failed: "failed",
  running: "changed",
  queued: "skipped",
};

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
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Runs</h1>
        {can("runs:trigger") && (
          <Button asChild>
            <Link to="/runs/new">New Run</Link>
          </Button>
        )}
      </div>

      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {!loading && runs.length === 0 && <p className="text-sm text-muted-foreground">No runs yet.</p>}

      <div className="flex flex-col gap-2">
        {runs.map((run) => (
          <Link key={run.id} to={`/runs/${run.id}`}>
            <Card className="transition-colors duration-150 hover:border-primary/50">
              <CardContent className="flex items-center justify-between p-4">
                <div className="flex flex-col gap-1">
                  <span className="font-medium">
                    {run.playbook_name} → {run.inventory_name}
                    {run.group_name ? ` / ${run.group_name}` : ""}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {run.triggered_by} · {new Date(run.created_at).toLocaleString()}
                    {run.become && " · become"}
                    {run.check_mode && " · check"}
                    {run.diff_mode && " · diff"}
                  </span>
                </div>
                <Badge variant={STATUS_VARIANT[run.status]}>{run.status}</Badge>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
