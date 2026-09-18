import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/context/auth-context";
import { api, type HealthStatus } from "@/lib/api";

export function DashboardPage() {
  const { user, logout } = useAuth();
  const [health, setHealth] = React.useState<HealthStatus | null>(null);
  const [healthError, setHealthError] = React.useState<string | null>(null);

  React.useEffect(() => {
    api.health().then(setHealth).catch(() => setHealthError("Backend unreachable"));
  }, []);

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="mx-auto flex max-w-2xl flex-col gap-6">
        <header className="flex items-center justify-between">
          <h1 className="font-mono text-2xl text-primary">AnsiDeck</h1>
          <div className="flex items-center gap-3">
            <span className="text-sm text-muted-foreground">{user?.username}</span>
            <Button variant="outline" size="sm" onClick={() => logout()}>
              Log out
            </Button>
          </div>
        </header>

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

        <Card>
          <CardHeader>
            <CardTitle>Run status palette</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="rounded-md bg-muted p-4 font-mono text-sm leading-relaxed">
              <span className="text-status-ok">ok:</span> [target-01] =&gt; playbook applied cleanly
              {"\n"}
              <span className="text-status-changed">changed:</span> [target-02] =&gt; state was
              updated
              {"\n"}
              <span className="text-status-skipped">skipping:</span> [target-03] =&gt; condition
              not met
              {"\n"}
              <span className="text-status-failed">failed:</span> [target-04] =&gt; task returned
              non-zero
            </pre>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
