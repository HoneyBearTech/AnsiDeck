import { describe, expect, it, vi } from "vitest";

import { reply } from "@/test/fake-api";
import { renderApp } from "@/test/render";

function worker(overrides = {}) {
  return {
    id: "worker-a",
    slots: 2,
    isolated: true,
    egress_filtered: true,
    host_keys: true,
    ssh_certificates: true,
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
    expect(
      screen.getByText(
        /Connection refused. Runs and refreshes that use a secret kept there fail until it is back/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/last reachable never · AnsiDeck's token has 30 min left/)).toBeInTheDocument();
  });

  it("says that runs wait for the secret store, and since when it is down", async () => {
    const { screen } = renderApp("/workers", {
      routes: {
        "GET /workers": [worker()],
        "GET /secret-store/status": {
          ...STORE_DOWN,
          wait_minutes: 15,
          outage_kind: "unreachable",
          outage_since: "2026-10-15T12:00:00Z",
        },
      },
    });
    expect(
      await screen.findByText(
        /Runs and refreshes that use a secret kept there wait for it \(up to 15 min\), then fail/,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/Unavailable since .*: what needs it is held in the queue/)).toBeInTheDocument();
  });

  it("shows which workers keep their runs away from the API and cloud metadata", async () => {
    const { screen } = renderApp("/workers", {
      routes: {
        "GET /workers": [
          worker(),
          worker({ id: "worker-open", egress_filtered: false }),
          worker({ id: "worker-dev", isolated: false, egress_filtered: false }),
          worker({ id: "worker-old", egress_filtered: null }),
        ],
        "GET /secret-store/status": { enabled: false },
      },
    });
    expect(await screen.findByText(/A worker lets its runs reach the API and cloud metadata/)).toBeInTheDocument();
    expect(screen.getAllByText("egress filtered")).toHaveLength(1);
    expect(screen.getAllByText("egress open")).toHaveLength(1); // not for the unisolated one
    expect(screen.getByText("worker-open").parentElement).toHaveTextContent("egress open");
  });

  it("says which workers are too old to check SSH host keys", async () => {
    const { screen } = renderApp("/workers", {
      routes: {
        "GET /workers": [worker(), worker({ id: "worker-old", host_keys: null })],
        "GET /secret-store/status": { enabled: false },
      },
    });
    expect(await screen.findByText("A worker doesn't check SSH host keys")).toBeInTheDocument();
    expect(screen.getAllByText("no host key checks")).toHaveLength(1);
    expect(screen.getByText("worker-old").parentElement).toHaveTextContent("no host key checks");
  });

  it("marks online workers too old for SSH certificates", async () => {
    const { screen } = renderApp("/workers", {
      routes: {
        "GET /workers": [
          worker(),
          worker({ id: "worker-prev", ssh_certificates: false }),
          worker({ id: "worker-gone", ssh_certificates: false, online: false }),
        ],
        "GET /secret-store/status": { enabled: false },
      },
    });
    await screen.findByText("worker-prev");
    expect(screen.getAllByText("no SSH certificates")).toHaveLength(1);
    expect(screen.getByText("worker-prev").parentElement).toHaveTextContent("no SSH certificates");
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
