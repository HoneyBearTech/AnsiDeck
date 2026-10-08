import { AnsiUp } from "ansi_up";
import * as React from "react";

import { runWebSocketUrl } from "@/lib/api";

interface LogLine {
  key: string;
  html: string;
}

// Lines are kept in chunks that never change once full, each a memoized component: a new line
// re-renders only the last chunk, not every line so far (a 100k-line run would otherwise
// take seconds per update). Lines that arrive within one frame are added in one update.
const CHUNK_LINES = 200;

interface Chunk {
  key: number;
  lines: LogLine[];
}

function appendLines(chunks: Chunk[], added: LogLine[]): Chunk[] {
  const next = chunks.slice(0, -1);
  let last = chunks.at(-1);
  for (const line of added) {
    if (!last || last.lines.length >= CHUNK_LINES) {
      if (last) next.push(last);
      last = { key: next.length, lines: [] };
    } else if (last === chunks.at(-1)) {
      last = { key: last.key, lines: [...last.lines] }; // a new object: memo sees the change
    }
    last.lines.push(line);
  }
  if (last) next.push(last);
  return next;
}

const LogChunk = React.memo(function LogChunk({ lines }: { lines: LogLine[] }) {
  return lines.map((line) => (
    <div
      key={line.key}
      className="whitespace-pre-wrap [overflow-wrap:anywhere]"
      dangerouslySetInnerHTML={{ __html: line.html }}
    />
  ));
});

// The server closes with 1000 once the run has finished and every line was sent, and with
// 1008 when the viewer may not read this run. Any other close cut the output short.
const CLOSE_COMPLETE = 1000;
const CLOSE_DENIED = 1008;
const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000];
// Handshakes that fail in a row (the server is down, or refused the socket before it opened).
const MAX_FAILED_CONNECTS = 6;

type StreamState = "streaming" | "reconnecting" | "complete" | "unavailable";

// Ansible doesn't colour its output without a terminal: lines are coloured by what they report,
// as the CLI would. The classes are fixed strings; the text itself goes through ansi_up (escaped).
const LINE_CLASSES: [RegExp, string][] = [
  [/^(PLAY|TASK|RUNNING HANDLER|PLAY RECAP)\b/, "font-semibold text-foreground"],
  [/^(ok|included):/, "text-status-ok"],
  [/^changed:/, "text-status-changed"],
  [/^(fatal|failed):|^(ERROR!|\[ERROR\])/, "text-status-failed"],
  [/^skipping:|^\.\.\.ignoring/, "text-status-skipped"],
  [/^\[(WARNING|DEPRECATION WARNING)\]/, "text-status-changed"],
];
const RECAP_LINE = /\bok=\d+\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)/;

function lineClass(line: string): string | null {
  const recap = RECAP_LINE.exec(line);
  if (recap) {
    if (Number(recap[2]) > 0 || Number(recap[3]) > 0) return "text-status-failed";
    return Number(recap[1]) > 0 ? "text-status-changed" : "text-status-ok";
  }
  return LINE_CLASSES.find(([pattern]) => pattern.test(line))?.[1] ?? null;
}

// Terminal hyperlinks (OSC 8, `ESC ] 8 ; params ; url ST`, and the empty one that ends them):
// output comes from playbooks, repositories and managed hosts, so a link's text could say
// anything. The text stays; the link goes.
// oxlint-disable-next-line no-control-regex -- matching terminal escape sequences is the point
const OSC8 = /\u001b\]8;[^;\u0007\u001b]*;[^\u0007\u001b]*(?:\u001b\\|\u0007)/g;

// One converter per line: ansi_up keeps colour state between calls, so a colour left open
// (black on black, say) would otherwise carry into later lines and hide them.
function lineToHtml(line: string): string {
  const ansiUp = new AnsiUp();
  ansiUp.url_allowlist = {}; // and never a link, whatever slips past OSC8
  return ansiUp.ansi_to_html(line.replace(OSC8, ""));
}

function toHtml(stdout: string): string {
  const coloured = stdout.includes("\u001b["); // already coloured: keep its own colours
  return stdout
    .split(/\r?\n/)
    .map((line) => {
      const html = lineToHtml(line);
      const cls = coloured ? null : lineClass(line);
      return cls ? `<span class="${cls}">${html}</span>` : html;
    })
    .join("\n");
}

/** A run's output as it is produced; `follow` keeps the newest line in view (for a live run). */
export function LiveLogViewer({ runId, follow = true }: { runId: number; follow?: boolean }) {
  const [chunks, setChunks] = React.useState<Chunk[]>([]);
  const [state, setState] = React.useState<StreamState>("streaming");
  const containerRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect -- a new run id starts a new stream from empty
    setChunks([]);
    setState("streaming");
    let received = 0; // every log line, shown or not: the resume point for ?from=
    let shown = 0;
    let pending: LogLine[] = [];
    let frame = 0;

    function flush() {
      cancelAnimationFrame(frame);
      frame = 0;
      if (pending.length === 0) return;
      const added = pending;
      pending = [];
      setChunks((prev) => appendLines(prev, added));
    }
    let attempt = 0;
    let failedConnects = 0;
    let disposed = false;
    let socket: WebSocket;
    let timer: ReturnType<typeof setTimeout>;

    function connect() {
      let opened = false;
      socket = new WebSocket(runWebSocketUrl(runId, received));

      socket.addEventListener("open", () => {
        opened = true;
        failedConnects = 0;
        setState("streaming");
      });

      socket.addEventListener("message", (event: MessageEvent<string>) => {
        received += 1;
        attempt = 0;
        let data: { stdout?: unknown; counter?: unknown };
        try {
          data = JSON.parse(event.data);
        } catch {
          return;
        }
        if (typeof data.stdout !== "string" || data.stdout.length === 0) return;
        pending.push({ key: `${data.counter ?? "e"}-${shown}`, html: toHtml(data.stdout) });
        shown += 1;
        if (!frame) frame = requestAnimationFrame(flush);
      });

      socket.addEventListener("close", (event: CloseEvent) => {
        if (disposed) return;
        flush(); // a hidden tab gets no animation frames: show what came before saying so
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
      });
    }
    connect();

    return () => {
      disposed = true;
      cancelAnimationFrame(frame);
      clearTimeout(timer);
      socket.close();
    };
  }, [runId]);

  const followRef = React.useRef(follow);
  React.useEffect(() => {
    followRef.current = follow;
  }, [follow]);
  React.useEffect(() => {
    if (followRef.current) containerRef.current?.scrollTo({ top: containerRef.current.scrollHeight });
    // oxlint-disable-next-line react/exhaustive-effect-dependencies -- scroll to the bottom whenever lines arrive
  }, [chunks]);

  return (
    <div className="flex flex-col gap-2">
      <div
        ref={containerRef}
        className="max-h-[32rem] overflow-y-auto rounded-md bg-muted p-4 font-mono text-sm leading-relaxed"
      >
        {chunks.length === 0 && (
          <p className="text-muted-foreground">
            {state === "complete" ? "This run produced no output." : "Waiting for output…"}
          </p>
        )}
        {chunks.map((chunk) => (
          <LogChunk key={chunk.key} lines={chunk.lines} />
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
