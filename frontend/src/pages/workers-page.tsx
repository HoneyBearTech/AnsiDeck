import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { api, ApiError, type WorkerInfo } from "@/lib/api";

const REFRESH_MS = 5000;

export function WorkersPage() {
  const [workers, setWorkers] = React.useState<WorkerInfo[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let active = true;
    function load() {
      api
        .listWorkers()
        .then((list) => {
          if (!active) return;
          setWorkers(list);
          setError(null);
        })
        .catch((err) => {
          if (active) setError(err instanceof ApiError ? err.message : "Something went wrong");
        });
    }
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const online = workers?.filter((w) => w.online) ?? [];
  const slots = online.reduce((sum, w) => sum + w.slots, 0);
  const busy = online.reduce((sum, w) => sum + w.running, 0);
  const unisolated = online.filter((w) => w.isolated === false);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">Workers</h1>
        <p className="text-sm text-muted-foreground">
          Worker processes that run playbooks. A worker counts as online while it keeps reporting in (every
          few seconds); workers not seen for a day drop off this list.
        </p>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
      {workers === null && !error && <p className="text-sm text-muted-foreground">Loading…</p>}

      {workers !== null &&
        (online.length === 0 ? (
          <div className="rounded-md bg-destructive/10 p-4">
            <p className="text-sm font-medium text-destructive">No worker is online</p>
            <p className="text-sm text-destructive">
              Queued runs wait until a worker starts. With Docker Compose:{" "}
              <code>docker compose up -d worker</code> (add <code>--scale worker=N</code> for more).
            </p>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            {online.length} online · {busy} of {slots} slot{slots === 1 ? "" : "s"} busy
          </p>
        ))}

      {unisolated.length > 0 && (
        <div className="rounded-md bg-status-changed/10 p-4">
          <p className="text-sm font-medium text-status-changed">
            {unisolated.length === 1 ? "A worker runs" : `${unisolated.length} workers run`} playbooks without
            isolation
          </p>
          <p className="text-sm text-status-changed">
            Its playbooks run as the worker's own user and can read other runs' files. Fine for development
            only; in production a worker refuses to start this way. Run it as docker-compose.yml does (as root
            with only the SETUID, SETGID, CHOWN and KILL capabilities).
          </p>
        </div>
      )}

      <div className="flex flex-col gap-2">
        {workers?.map((worker) => (
          <Card key={worker.id}>
            <CardContent className="flex flex-wrap items-center justify-between gap-2 p-4">
              <div className="flex items-center gap-2">
                <Badge variant={worker.online ? "ok" : "skipped"}>
                  {worker.online ? "online" : "offline"}
                </Badge>
                {worker.isolated === true && (
                  <Badge variant="outline" title="Each slot runs its playbooks as a user of its own">
                    isolated
                  </Badge>
                )}
                {worker.isolated === false && (
                  <Badge variant="changed" title="Playbooks run as the worker's own user">
                    not isolated
                  </Badge>
                )}
                <span className="font-mono text-sm">{worker.id}</span>
              </div>
              <span className="text-sm text-muted-foreground">
                {worker.running} of {worker.slots} slot{worker.slots === 1 ? "" : "s"} busy · last seen{" "}
                {new Date(worker.last_seen_at).toLocaleString()} · since{" "}
                {new Date(worker.first_seen_at).toLocaleString()}
              </span>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
