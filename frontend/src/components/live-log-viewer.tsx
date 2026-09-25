import { AnsiUp } from "ansi_up";
import * as React from "react";

import { runWebSocketUrl } from "@/lib/api";

interface LogLine {
  key: string;
  html: string;
}

// The server closes with 1000 once the run has finished and every line was sent, and with
// 1008 when the viewer may not read this run. Any other close cut the output short.
const CLOSE_COMPLETE = 1000;
const CLOSE_DENIED = 1008;
const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000];
// Handshakes that fail in a row (the server is down, or refused the socket before it opened).
const MAX_FAILED_CONNECTS = 6;

type StreamState = "streaming" | "reconnecting" | "complete" | "unavailable";

export function LiveLogViewer({ runId }: { runId: number }) {
  const [lines, setLines] = React.useState<LogLine[]>([]);
  const [state, setState] = React.useState<StreamState>("streaming");
  const containerRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    setLines([]);
    setState("streaming");
    const ansiUp = new AnsiUp();
    let received = 0; // every log line, shown or not: the resume point for ?from=
    let attempt = 0;
    let failedConnects = 0;
    let disposed = false;
    let socket: WebSocket;
    let timer: ReturnType<typeof setTimeout>;

    function connect() {
      let opened = false;
      socket = new WebSocket(runWebSocketUrl(runId, received));

      socket.onopen = () => {
        opened = true;
        failedConnects = 0;
        setState("streaming");
      };

      socket.onmessage = (event: MessageEvent<string>) => {
        received += 1;
        attempt = 0;
        let data: { stdout?: unknown; counter?: unknown };
        try {
          data = JSON.parse(event.data);
        } catch {
          return;
        }
        if (typeof data.stdout !== "string" || data.stdout.length === 0) return;
        const html = ansiUp.ansi_to_html(data.stdout);
        setLines((prev) => [...prev, { key: `${data.counter ?? "e"}-${prev.length}`, html }]);
      };

      socket.onclose = (event: CloseEvent) => {
        if (disposed) return;
        if (event.code === CLOSE_COMPLETE) {
          setState("complete");
          return;
        }
        if (!opened) failedConnects += 1;
        if (event.code === CLOSE_DENIED || failedConnects >= MAX_FAILED_CONNECTS) {
          setState("unavailable");
          return;
        }
        setState("reconnecting");
        const delay = RECONNECT_DELAYS_MS[Math.min(attempt, RECONNECT_DELAYS_MS.length - 1)];
        attempt += 1;
        timer = setTimeout(connect, delay);
      };
    }
    connect();

    return () => {
      disposed = true;
      clearTimeout(timer);
      socket.close();
    };
  }, [runId]);

  React.useEffect(() => {
    containerRef.current?.scrollTo({ top: containerRef.current.scrollHeight });
  }, [lines]);

  return (
    <div className="flex flex-col gap-2">
      <div
        ref={containerRef}
        className="max-h-[32rem] overflow-y-auto rounded-md bg-muted p-4 font-mono text-sm leading-relaxed"
      >
        {lines.length === 0 && (
          <p className="text-muted-foreground">
            {state === "complete" ? "This run produced no output." : "Waiting for output…"}
          </p>
        )}
        {lines.map((line) => (
          <div key={line.key} dangerouslySetInnerHTML={{ __html: line.html }} />
        ))}
      </div>
      {state === "reconnecting" && (
        <p className="text-xs text-muted-foreground">Connection lost. Reconnecting…</p>
      )}
      {state === "unavailable" && (
        <p className="text-xs text-destructive">Live output is unavailable. Reload the page to try again.</p>
      )}
    </div>
  );
}
