import { act, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FakeWebSocket } from "@/test/fake-websocket";
import { inventory, playbook, run, viewerUser } from "@/test/fixtures";
import { renderApp } from "@/test/render";

const ROUTES = { "GET /users": [], "GET /runs": [run()], "GET /playbooks": [playbook()], "GET /inventories": [inventory()], "GET /run-templates": [], "GET /credentials": [] };

describe("header", () => {
  it("groups admin pages in a menu and keeps Account and Log out in the user menu", async () => {
    const { user, screen } = renderApp("/runs", { routes: ROUTES });
    const nav = await screen.findByRole("navigation", { name: "Main" });
    for (const name of ["Dashboard", "Playbooks", "Inventories", "Runs", "Templates", "Credentials", "Vault", "Galaxy"]) {
      expect(within(nav).getByRole("link", { name })).toBeInTheDocument();
    }
    expect(within(nav).getByRole("link", { name: "Runs" })).toHaveClass("text-primary");
    expect(within(nav).queryByRole("link", { name: "Users" })).not.toBeInTheDocument();

    await user.click(within(nav).getByRole("button", { name: "Admin" }));
    for (const name of ["Projects", "Users", "Audit log", "Workers", "Notifications"]) {
      expect(await screen.findByRole("menuitem", { name })).toBeInTheDocument();
    }
    await user.click(screen.getByRole("menuitem", { name: "Users" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Users" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "admin" }));
    expect(await screen.findByText(/Signed in as/)).toHaveTextContent("Signed in as admin (global admin)");
    await user.click(screen.getByRole("menuitem", { name: "Account" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Account" })).toBeInTheDocument();
  });

  it("shows no Admin menu to someone without admin pages", async () => {
    const { screen } = renderApp("/runs", { user: viewerUser(), routes: ROUTES });
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("button", { name: "Admin" })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Credentials" })).not.toBeInTheDocument();
  });

  it("opens a menu with every page on small screens, and closes it on navigation", async () => {
    const { user, screen } = renderApp("/runs", { routes: ROUTES });
    const toggle = await screen.findByRole("button", { name: "Open menu" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(screen.getByRole("button", { name: "Close menu" })).toHaveAttribute("aria-expanded", "true");
    const menu = document.getElementById("mobile-menu")!;
    expect(within(menu).getByText("Admin")).toBeInTheDocument();
    expect(within(menu).getByRole("link", { name: "Audit log" })).toHaveAttribute("href", "/audit");
    expect(within(menu).getByText("admin (global admin)")).toBeInTheDocument();
    await user.click(within(menu).getByRole("link", { name: "Playbooks" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Playbooks" })).toBeInTheDocument();
    expect(document.getElementById("mobile-menu")).toBeNull();
  });

  it("switches between the menu button and the full nav at 1280 px", async () => {
    // jsdom has no layout, so this pins the breakpoint classes: below xl the full nav no longer fits.
    const { screen } = renderApp("/runs", { routes: ROUTES });
    expect(await screen.findByRole("button", { name: "Open menu" })).toHaveClass("xl:hidden");
    const [desktopNav] = screen.getAllByRole("navigation", { name: "Main" });
    expect(desktopNav).toHaveClass("hidden", "xl:flex");
  });
});

describe("run output", () => {
  it("colours Ansible's lines, keeps their line breaks and follows only a live run", async () => {
    const { screen, container } = renderApp("/runs/7", { routes: { "GET /runs/:id": run() } });
    expect(await screen.findByRole("heading", { name: "Output" })).toBeInTheDocument();
    const socket = await FakeWebSocket.opened();
    act(() => {
      socket.open();
      socket.emit({ counter: 1, stdout: "TASK [Say hi] ****" });
      socket.emit({ counter: 2, stdout: "ok: [web1]\nchanged: [web2]\nskipping: [web3]\nfatal: [web4]: FAILED!" });
      socket.emit({ counter: 3, stdout: "PLAY RECAP ****\nweb1 : ok=1 changed=0 unreachable=0 failed=0\nweb2 : ok=1 changed=1 unreachable=0 failed=0\nweb4 : ok=0 changed=0 unreachable=0 failed=1" });
      socket.emit({ counter: 4, stdout: "<script>alert(1)</script>" });
    });
    expect(await screen.findByText("ok: [web1]")).toHaveClass("text-status-ok");
    expect(screen.getByText("changed: [web2]")).toHaveClass("text-status-changed");
    expect(screen.getByText("skipping: [web3]")).toHaveClass("text-status-skipped");
    expect(screen.getByText("fatal: [web4]: FAILED!")).toHaveClass("text-status-failed");
    expect(screen.getByText("TASK [Say hi] ****")).toHaveClass("font-semibold");
    expect(screen.getByText("web2 : ok=1 changed=1 unreachable=0 failed=0")).toHaveClass("text-status-changed");
    expect(screen.getByText("web4 : ok=0 changed=0 unreachable=0 failed=1")).toHaveClass("text-status-failed");
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
    const recap = screen.getByText("PLAY RECAP ****").parentElement!;
    expect(recap).toHaveClass("whitespace-pre-wrap");
    expect(recap.textContent).toContain("****\nweb1");
  });
});
