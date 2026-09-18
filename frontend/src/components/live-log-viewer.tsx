import { AnsiUp } from "ansi_up";
import * as React from "react";

import { runWebSocketUrl } from "@/lib/api";

interface LogLine {
  key: string;
  html: string;
}

export function LiveLogViewer({ runId }: { runId: number }) {
  const [lines, setLines] = React.useState<LogLine[]>([]);
  const containerRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    setLines([]);
    const ansiUp = new AnsiUp();
    const socket = new WebSocket(runWebSocketUrl(runId));

    socket.onmessage = (event: MessageEvent<string>) => {
      let data: { stdout?: unknown; counter?: unknown };
      try {
        data = JSON.parse(event.data);
      } catch {
        return;
      }
      if (typeof data.stdout !== "string" || data.stdout.length === 0) return;
      setLines((prev) => [
        ...prev,
        { key: `${data.counter ?? "e"}-${prev.length}`, html: ansiUp.ansi_to_html(data.stdout as string) },
      ]);
    };

    return () => socket.close();
  }, [runId]);

  React.useEffect(() => {
    containerRef.current?.scrollTo({ top: containerRef.current.scrollHeight });
  }, [lines]);

  return (
    <div
      ref={containerRef}
      className="max-h-[32rem] overflow-y-auto rounded-md bg-muted p-4 font-mono text-sm leading-relaxed"
    >
      {lines.length === 0 && <p className="text-muted-foreground">Waiting for output…</p>}
      {lines.map((line) => (
        <div key={line.key} dangerouslySetInnerHTML={{ __html: line.html }} />
      ))}
    </div>
  );
}
