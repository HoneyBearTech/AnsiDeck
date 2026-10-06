// Every page with enough fake API data to render its full content: used by the axe test (a11y.test.tsx)
// and the browser layout check (e2e/layout.spec.ts), so it must not import Vitest.
import type { User } from "@/lib/api";

import { reply, type Routes } from "./api-routes";
import {
  adminUser,
  CATALOG,
  credential,
  graph,
  gitSource,
  inventory,
  mergedHost,
  playbook,
  run,
  runTemplate,
  targets,
  vaultPassword,
} from "./fixtures";

/** What the app asks for on every page: who is signed in, sign-in providers, health. */
export function baseRoutes(user: User | null = adminUser()): Routes {
  return {
    "GET /auth/me": user ? user : reply(401, { detail: "Not authenticated" }),
    "GET /auth/providers": { oidc: { enabled: false, label: "SSO" }, github: { enabled: false, label: "GitHub" } },
    "GET /health": { status: "ok", service: "ansideck-backend" },
    "GET /secret-store/info": { enabled: false, label: "OpenBao", base_path: null, path_rules: "" },
  };
}

// Enough data for every page to render its full content.
export const PAGE_ROUTES: Routes = {
  "GET /playbooks": [playbook()],
  "GET /playbooks/:id": playbook(),
  "GET /inventories": [inventory()],
  "GET /inventories/:id": inventory(),
  "GET /inventories/:id/sources": [],
  "GET /inventories/:id/targets": targets(),
  "GET /inventories/:id/snapshot": null,
  "GET /inventories/:id/graph": graph(),
  "GET /inventories/:id/hosts": { total: 1, hosts: [mergedHost()] },
  "GET /credentials": [credential()],
  "GET /vault-passwords": [vaultPassword()],
  "GET /runs": [run()],
  "GET /runs/:id": run(),
  "GET /run-templates": [runTemplate(), runTemplate({ id: 4, name: "Broken", missing: ["credential"] })],
  "GET /projects": [{ id: 1, name: "Default", description: null, created_at: "2026-10-05T12:00:00Z", my_role: "admin" }],
  "GET /projects/:id/git-sources": [gitSource()],
  "GET /users": [],
  "GET /audit": { items: [], total: 0 },
  "GET /workers": [],
  "GET /secret-store/status": { enabled: false, label: "OpenBao", url: null, ok: null, reachable: null, sealed: null, version: null, token_ttl: null, error_kind: null, error: null, checked_at: null, last_ok_at: null },
  "GET /notifications/catalog": CATALOG,
  "GET /notifications/channels": [],
  "GET /projects/:id/notifications/channels": [],
  "GET /galaxy/requirements": { content: "" },
  "GET /galaxy/installed": { collections: [], roles: [] },
  "GET /galaxy/installs": [],
};

/** Each page and the name of its <h1>. */
export const PAGES: [string, string | RegExp][] = [
  ["/", "Dashboard"],
  ["/account", "Account"],
  ["/playbooks", "Playbooks"],
  ["/playbooks/1", "Edit playbook"],
  ["/inventories", "Inventories"],
  ["/inventories/1", "lab"],
  ["/inventories/1/graph", "Group graph"],
  ["/credentials", "Credentials"],
  ["/vault", "Vault"],
  ["/galaxy", "Galaxy"],
  ["/runs", "Runs"],
  ["/runs/new", "New run"],
  ["/runs/7", /site\.yml →\s+lab/],
  ["/templates", "Templates"],
  ["/users", "Users"],
  ["/audit", "Audit log"],
  ["/workers", "Workers"],
  ["/notifications", "Notifications"],
  ["/projects", "Projects"],
];
