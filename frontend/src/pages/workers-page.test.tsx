import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { renderApp } from "@/test/render";

function worker(overrides = {}) {
  return {
    id: "worker-a",
    slots: 2,
    isolated: true,
    running: 1,
    online: true,
    first_seen_at: "2026-10-05T10:00:00Z",
    last_seen_at: "2026-10-05T12:00:00Z",
    ...overrides,
  };
}

const STORE_DOWN = {
  enabled: true,
  label: "OpenBao",
  url: "https://bao.lan:8200",
  ok: false,
  reachable: false,
  sealed: true,
  version: "2.7.1",
  token_ttl: 1800,
  error_kind: "unreachable",
  error: "connection refused",
  checked_at: 1_780_000_000,
  last_ok_at: null,
};

describe("workers", () => {
  it("shows capacity, isolation and the secret store's health", async () => {
    const { screen } = renderApp("/workers", {
      routes: {
        "GET /workers": [worker(), worker({ id: "worker-b", isolated: false, running: 0, slots: 1 }), worker({ id: "old", online: false, isolated: null })],
        "GET /secret-store/status": STORE_DOWN,
      },
    });
    expect(await screen.findByText("2 online · 1 of 3 slots busy")).toBeInTheDocument();
    expect(screen.getByText(/A worker runs playbooks without isolation/)).toBeInTheDocument();
    expect(screen.getByText("not isolated")).toBeInTheDocument();
    expect(screen.getByText("offline")).toBeInTheDocument();
    expect(await screen.findByText("Secret store: OpenBao")).toBeInTheDocument();
    expect(screen.getByText("sealed")).toBeInTheDocument();
    expect(screen.getByText(/Connection refused. Runs that use a secret kept there fail/)).toBeInTheDocument();
    expect(screen.getByText(/last reachable never · AnsiDeck's token has 30 min left/)).toBeInTheDocument();
  });

  it("warns when no worker is online and keeps polling", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { api, screen } = renderApp("/workers", {
        routes: { "GET /workers": [], "GET /secret-store/status": reply(500) },
      });
      expect(await screen.findByText("No worker is online")).toBeInTheDocument();
      api.set({
        "GET /workers": [worker()],
        "GET /secret-store/status": { ...STORE_DOWN, ok: null, sealed: false, error: null, token_ttl: null, version: null, url: null },
      });
      await vi.advanceTimersByTimeAsync(5100);
      expect(await screen.findByText("1 online · 1 of 2 slots busy")).toBeInTheDocument();
      expect(screen.getByText("not checked yet")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows why the list can't load", async () => {
    const { screen } = renderApp("/workers", {
      routes: { "GET /workers": reply(403, { detail: "Not allowed" }), "GET /secret-store/status": reply(403) },
    });
    expect(await screen.findByText("Not allowed")).toBeInTheDocument();
  });
});
