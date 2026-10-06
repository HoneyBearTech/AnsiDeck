import { ChevronRight } from "lucide-react";
import * as React from "react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/page-header";
import { RunRow } from "@/components/run-row";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/context/auth-context";
import { api, type Run } from "@/lib/api";

const ACTIVE: Run["status"][] = ["queued", "running"];
const POLL_MS = 5000;

function CountCard({ to, label, count }: { to: string; label: string; count: number | null }) {
  return (
    <Link to={to} className="group block rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
      <Card className="h-full transition-colors duration-150 group-hover:border-primary/50">
        <CardContent className="flex items-center justify-between gap-2 p-4">
          <div className="flex flex-col gap-1">
            <span className="text-sm text-muted-foreground">{label}</span>
            <span className="font-mono text-2xl text-foreground">{count ?? "…"}</span>
          </div>
          <ChevronRight aria-hidden="true" className="size-4 text-muted-foreground group-hover:text-foreground" />
        </CardContent>
      </Card>
    </Link>
  );
}

function RunSection({
  title,
  runs,
  empty,
  more,
}: {
  title: string;
  runs: Run[] | null;
  empty: string;
  more?: { to: string; label: string };
}) {
  const id = `section-${title.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <section aria-labelledby={id} className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <h2 id={id} className="font-medium">
          {title}
        </h2>
        {more && (
          <Link to={more.to} className="text-sm text-primary hover:underline">
            {more.label}
          </Link>
        )}
      </div>
      {runs === null ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : runs.length === 0 ? (
        <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">{empty}</p>
      ) : (
        <div className="flex flex-col gap-2">
          {runs.map((run) => (
            <RunRow key={run.id} run={run} />
          ))}
        </div>
      )}
    </section>
  );
}

export function DashboardPage() {
  const { can } = useAuth();
  const canListCredentials = can("secrets:list");
  const [active, setActive] = React.useState<Run[] | null>(null);
  const [failures, setFailures] = React.useState<Run[] | null>(null);
  const [recent, setRecent] = React.useState<Run[] | null>(null);
  const [counts, setCounts] = React.useState<Record<string, number | null>>({});
  const [unreachable, setUnreachable] = React.useState(false);

  React.useEffect(() => {
    const failed = () => setUnreachable(true);
    api.listRuns({ status: ["failed", "timed_out"], limit: 5 }).then(setFailures, failed);
    api.listRuns({ limit: 8 }).then(setRecent, failed);
    // Counts are best-effort: a failed or forbidden call leaves its card on "…".
    const count = (key: string) => (items: unknown[]) => setCounts((c) => ({ ...c, [key]: items.length }));
    api.listPlaybooks().then(count("playbooks"), () => {});
    api.listInventories().then(count("inventories"), () => {});
    api.listRunTemplates().then(count("templates"), () => {});
    if (canListCredentials) api.listCredentials().then(count("credentials"), () => {});
  }, [canListCredentials]);

  // What's running now, refreshed while the page is open.
  React.useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    async function load() {
      try {
        const runs = await api.listRuns({ status: ACTIVE, limit: 20 });
        if (alive) setActive(runs);
      } catch {
        if (alive) setUnreachable(true);
      }
      if (alive) timer = setTimeout(load, POLL_MS);
    }
    load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, []);

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title="Dashboard"
        description="What's running, what failed lately, and the latest runs."
        actions={
          can("runs:trigger") && (
            <>
              <Button variant="outline" asChild>
                <Link to="/templates">Templates</Link>
              </Button>
              <Button asChild>
                <Link to="/runs/new">New run</Link>
              </Button>
            </>
          )
        }
      />

      {unreachable && (
        <p role="alert" className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
          The AnsiDeck API couldn't be reached. Check that the backend is running, then reload the page.
        </p>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <CountCard to="/playbooks" label="Playbooks" count={counts["playbooks"] ?? null} />
        <CountCard to="/inventories" label="Inventories" count={counts["inventories"] ?? null} />
        <CountCard to="/templates" label="Templates" count={counts["templates"] ?? null} />
        {canListCredentials ? (
          <CountCard to="/credentials" label="Credentials" count={counts["credentials"] ?? null} />
        ) : (
          <CountCard to="/runs" label="Recent runs" count={recent?.length ?? null} />
        )}
      </div>

      <RunSection title="Running now" runs={active} empty="Nothing is running or waiting to run." />
      <RunSection title="Recent failures" runs={failures} empty="No failed runs. 🎉" />
      <RunSection title="Latest runs" runs={recent} empty="No runs yet." more={{ to: "/runs", label: "All runs" }} />
    </div>
  );
}
