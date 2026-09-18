import * as React from "react";
import { Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api, type HealthStatus } from "@/lib/api";

function CountCard({ to, label, count }: { to: string; label: string; count: number | null }) {
  return (
    <Link to={to}>
      <Card className="transition-colors duration-150 hover:border-primary/50">
        <CardHeader>
          <CardTitle className="text-sm text-muted-foreground">{label}</CardTitle>
        </CardHeader>
        <CardContent>
          <span className="text-3xl font-mono text-foreground">{count ?? "…"}</span>
        </CardContent>
      </Card>
    </Link>
  );
}

export function DashboardPage() {
  const [health, setHealth] = React.useState<HealthStatus | null>(null);
  const [healthError, setHealthError] = React.useState<string | null>(null);
  const [playbookCount, setPlaybookCount] = React.useState<number | null>(null);
  const [inventoryCount, setInventoryCount] = React.useState<number | null>(null);
  const [credentialCount, setCredentialCount] = React.useState<number | null>(null);

  React.useEffect(() => {
    api.health().then(setHealth).catch(() => setHealthError("Backend unreachable"));
    api.listPlaybooks().then((p) => setPlaybookCount(p.length));
    api.listInventories().then((i) => setInventoryCount(i.length));
    api.listCredentials().then((c) => setCredentialCount(c.length));
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Backend status</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center gap-3">
          {health && <Badge variant="ok">{health.status}</Badge>}
          {healthError && <Badge variant="failed">{healthError}</Badge>}
          {!health && !healthError && <Badge>checking…</Badge>}
          <span className="text-sm text-muted-foreground">{health?.service}</span>
        </CardContent>
      </Card>

      <div className="grid grid-cols-3 gap-4">
        <CountCard to="/playbooks" label="Playbooks" count={playbookCount} />
        <CountCard to="/inventories" label="Inventories" count={inventoryCount} />
        <CountCard to="/credentials" label="Credentials" count={credentialCount} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Run status palette</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="rounded-md bg-muted p-4 font-mono text-sm leading-relaxed">
            <span className="text-status-ok">ok:</span> [target-01] =&gt; playbook applied cleanly
            {"\n"}
            <span className="text-status-changed">changed:</span> [target-02] =&gt; state was updated
            {"\n"}
            <span className="text-status-skipped">skipping:</span> [target-03] =&gt; condition not met
            {"\n"}
            <span className="text-status-failed">failed:</span> [target-04] =&gt; task returned non-zero
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
