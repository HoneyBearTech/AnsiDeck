import { ChevronRight } from "lucide-react";
import { Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/context/auth-context";
import type { Run } from "@/lib/api";
import { formatDuration, STATUS_VARIANT } from "@/lib/runs";

/** One run in a list: number, target, who and when, options, host outcome and status; opens the run. */
export function RunRow({ run }: { run: Run }) {
  const { user, activeProjectId } = useAuth();
  const project = activeProjectId === null ? user?.projects.find((p) => p.id === run.project_id) : undefined;
  const took = formatDuration(run.started_at, run.finished_at);
  const failedHosts = (run.hosts_failed ?? 0) + (run.hosts_unreachable ?? 0);
  const options = [
    run.become && "become",
    run.check_mode && "check",
    run.diff_mode && "diff",
    run.limit && `limit: ${run.limit}`,
  ].filter((o): o is string => Boolean(o));
  return (
    <Link to={`/runs/${run.id}`} className="group block rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
      <Card className="transition-colors duration-150 group-hover:border-primary/50">
        <CardContent className="flex items-center gap-3 p-4">
          <div className="flex min-w-0 flex-1 flex-col gap-1.5">
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-mono text-xs text-muted-foreground">#{run.id}</span>
              <span className="font-medium break-words">
                {run.playbook_name} <span className="whitespace-nowrap">→ {run.inventory_name}</span>
                {run.group_name && <span className="whitespace-nowrap"> / {run.group_name}</span>}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
              <span>{run.triggered_by}</span>
              <span>· {new Date(run.created_at).toLocaleString()}</span>
              {took && <span>· took {took}</span>}
              {run.hosts_total !== null && (
                <span className={failedHosts > 0 ? "text-status-failed" : undefined}>
                  · {run.hosts_total} {run.hosts_total === 1 ? "host" : "hosts"}
                  {failedHosts > 0 && `, ${failedHosts} failed`}
                </span>
              )}
              {run.git_commit && <span className="font-mono">· {run.git_commit.slice(0, 8)}</span>}
              {project && <Badge variant="outline">{project.name}</Badge>}
              {options.map((option) => (
                <Badge key={option} variant="outline">
                  {option}
                </Badge>
              ))}
            </div>
          </div>
          <Badge variant={STATUS_VARIANT[run.status]}>{run.status.replace("_", " ")}</Badge>
          <ChevronRight aria-hidden="true" className="size-4 shrink-0 text-muted-foreground group-hover:text-foreground" />
        </CardContent>
      </Card>
    </Link>
  );
}
