const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// The project the UI is currently working in (null = all projects, global admins
// only). Set by the auth context; list calls filter by it and create calls put
// new resources into it.
let activeProjectId: number | null = null;

export function setApiActiveProject(id: number | null): void {
  activeProjectId = id;
}

function scoped(path: string): string {
  return activeProjectId === null ? path : `${path}?project_id=${activeProjectId}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...init,
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(response.status, body?.detail ?? response.statusText);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

export interface HealthStatus {
  status: string;
  service: string;
}

export interface ProjectAccess {
  id: number;
  name: string;
  role: "admin" | "operator" | "viewer";
  permissions: string[];
}

export interface User {
  username: string;
  role: "admin" | "operator" | "viewer";
  // Union across the user's projects (everything for a global admin).
  permissions: string[];
  projects: ProjectAccess[];
}

export interface ProjectSummary {
  id: number;
  name: string;
  description: string | null;
  created_at: string;
  my_role: string | null;
}

export interface ProjectMember {
  user_id: number;
  username: string;
  is_active: boolean;
  role: "admin" | "operator" | "viewer";
}

export interface AdminUser {
  id: number;
  username: string;
  role: "admin" | "operator" | "viewer";
  is_active: boolean;
  created_by: string | null;
  created_at: string;
}

export interface AuditEvent {
  id: number;
  created_at: string;
  actor_username: string | null;
  project_id: number | null;
  action: string;
  target_type: string | null;
  target_id: number | null;
  target_name: string | null;
  outcome: "success" | "failure" | "denied";
  ip: string | null;
  detail: Record<string, unknown> | null;
}

export interface AuditPage {
  items: AuditEvent[];
  total: number;
}

export interface PlaybookSummary {
  id: number;
  name: string;
  project_id: number;
  created_at: string;
  updated_at: string;
}

export interface PlaybookDetail extends PlaybookSummary {
  content: string;
}

export interface InventorySummary {
  id: number;
  name: string;
  description: string | null;
  project_id: number;
}

export interface InventoryGroup {
  id: number;
  name: string;
}

export interface InventoryHost {
  id: number;
  hostname: string;
  vars: Record<string, unknown>;
  group_ids: number[];
}

export interface InventoryDetail extends InventorySummary {
  groups: InventoryGroup[];
  hosts: InventoryHost[];
}

export interface Credential {
  id: number;
  name: string;
  description: string | null;
  project_id: number;
  created_at: string;
}

export interface VaultPassword {
  id: number;
  name: string;
  description: string | null;
  project_id: number;
  created_at: string;
}

export interface VaultEncryptResult {
  vault_text: string;
  yaml_block: string;
}

export interface GalaxyInstall {
  id: number;
  status: "queued" | "running" | "success" | "failed";
  triggered_by: string;
  upgrade: boolean;
  return_code: number | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface GalaxyInstallDetail extends GalaxyInstall {
  requirements_snapshot: string;
  log: string;
}

export interface GalaxyItem {
  name: string;
  version: string | null;
}

export interface GalaxyInstalled {
  collections: GalaxyItem[];
  roles: GalaxyItem[];
}

export interface Run {
  id: number;
  project_id: number;
  playbook_name: string;
  inventory_name: string;
  group_name: string | null;
  credential_name: string;
  vault_password_name: string | null;
  become: boolean;
  check_mode: boolean;
  diff_mode: boolean;
  limit: string | null;
  extra_vars: Record<string, unknown> | null;
  status: "queued" | "running" | "success" | "failed";
  triggered_by: string;
  return_code: number | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export const api = {
  health: () => request<HealthStatus>("/health"),
  login: (username: string, password: string) =>
    request<User>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ ok: boolean }>("/auth/logout", { method: "POST" }),
  me: () => request<User>("/auth/me"),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: boolean }>("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    }),

  listProjects: () => request<ProjectSummary[]>("/projects"),
  createProject: (name: string, description?: string) =>
    request<ProjectSummary>("/projects", {
      method: "POST",
      body: JSON.stringify({ name, description }),
    }),
  updateProject: (id: number, payload: { name?: string; description?: string }) =>
    request<ProjectSummary>(`/projects/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteProject: (id: number) => request<void>(`/projects/${id}`, { method: "DELETE" }),
  listProjectMembers: (id: number) => request<ProjectMember[]>(`/projects/${id}/members`),
  addProjectMember: (id: number, username: string, role: ProjectMember["role"]) =>
    request<ProjectMember>(`/projects/${id}/members`, {
      method: "POST",
      body: JSON.stringify({ username, role }),
    }),
  setProjectMemberRole: (id: number, userId: number, role: ProjectMember["role"]) =>
    request<ProjectMember>(`/projects/${id}/members/${userId}`, {
      method: "PUT",
      body: JSON.stringify({ role }),
    }),
  removeProjectMember: (id: number, userId: number) =>
    request<void>(`/projects/${id}/members/${userId}`, { method: "DELETE" }),

  listUsers: () => request<AdminUser[]>("/users"),
  createUser: (username: string, password: string, role: AdminUser["role"], projectId?: number | null) =>
    request<AdminUser>("/users", {
      method: "POST",
      body: JSON.stringify({ username, password, role, project_id: projectId ?? undefined }),
    }),
  updateUser: (
    id: number,
    payload: {
      role?: AdminUser["role"];
      is_active?: boolean;
      password?: string;
    },
  ) =>
    request<AdminUser>(`/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteUser: (id: number) => request<void>(`/users/${id}`, { method: "DELETE" }),

  listAudit: (params: {
    limit: number;
    offset: number;
    action?: string;
    actor?: string;
    outcome?: string;
  }) => {
    const query = new URLSearchParams({
      limit: String(params.limit),
      offset: String(params.offset),
    });
    for (const key of ["action", "actor", "outcome"] as const) {
      if (params[key]) query.set(key, params[key]);
    }
    return request<AuditPage>(`/audit?${query.toString()}`);
  },

  listPlaybooks: () => request<PlaybookSummary[]>(scoped("/playbooks")),
  getPlaybook: (id: number) => request<PlaybookDetail>(`/playbooks/${id}`),
  createPlaybook: (name: string, content: string) =>
    request<PlaybookDetail>("/playbooks", {
      method: "POST",
      body: JSON.stringify({ name, content, project_id: activeProjectId ?? undefined }),
    }),
  updatePlaybook: (id: number, payload: { name?: string; content?: string }) =>
    request<PlaybookDetail>(`/playbooks/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  deletePlaybook: (id: number) => request<void>(`/playbooks/${id}`, { method: "DELETE" }),

  listInventories: () => request<InventorySummary[]>(scoped("/inventories")),
  getInventory: (id: number) => request<InventoryDetail>(`/inventories/${id}`),
  createInventory: (name: string, description?: string) =>
    request<InventoryDetail>("/inventories", {
      method: "POST",
      body: JSON.stringify({ name, description, project_id: activeProjectId ?? undefined }),
    }),
  updateInventory: (id: number, payload: { name?: string; description?: string }) =>
    request<InventoryDetail>(`/inventories/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  deleteInventory: (id: number) => request<void>(`/inventories/${id}`, { method: "DELETE" }),

  createGroup: (inventoryId: number, name: string) =>
    request<InventoryGroup>(`/inventories/${inventoryId}/groups`, {
      method: "POST",
      body: JSON.stringify({ name }),
    }),
  updateGroup: (inventoryId: number, groupId: number, name: string) =>
    request<InventoryGroup>(`/inventories/${inventoryId}/groups/${groupId}`, {
      method: "PUT",
      body: JSON.stringify({ name }),
    }),
  deleteGroup: (inventoryId: number, groupId: number) =>
    request<void>(`/inventories/${inventoryId}/groups/${groupId}`, {
      method: "DELETE",
    }),

  createHost: (
    inventoryId: number,
    payload: {
      hostname: string;
      vars?: Record<string, unknown>;
      group_ids?: number[];
    },
  ) =>
    request<InventoryHost>(`/inventories/${inventoryId}/hosts`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateHost: (
    inventoryId: number,
    hostId: number,
    payload: {
      hostname?: string;
      vars?: Record<string, unknown>;
      group_ids?: number[];
    },
  ) =>
    request<InventoryHost>(`/inventories/${inventoryId}/hosts/${hostId}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  deleteHost: (inventoryId: number, hostId: number) =>
    request<void>(`/inventories/${inventoryId}/hosts/${hostId}`, {
      method: "DELETE",
    }),

  listCredentials: () => request<Credential[]>(scoped("/credentials")),
  createCredential: (name: string, privateKey: string, description?: string) =>
    request<Credential>("/credentials", {
      method: "POST",
      body: JSON.stringify({
        name,
        description,
        private_key: privateKey,
        project_id: activeProjectId ?? undefined,
      }),
    }),
  deleteCredential: (id: number) => request<void>(`/credentials/${id}`, { method: "DELETE" }),

  listVaultPasswords: () => request<VaultPassword[]>(scoped("/vault-passwords")),
  createVaultPassword: (name: string, password: string, description?: string) =>
    request<VaultPassword>("/vault-passwords", {
      method: "POST",
      body: JSON.stringify({ name, description, password, project_id: activeProjectId ?? undefined }),
    }),
  deleteVaultPassword: (id: number) => request<void>(`/vault-passwords/${id}`, { method: "DELETE" }),
  encryptVaultString: (vaultPasswordId: number, plaintext: string, varName?: string) =>
    request<VaultEncryptResult>("/vault/encrypt", {
      method: "POST",
      body: JSON.stringify({
        vault_password_id: vaultPasswordId,
        plaintext,
        var_name: varName || null,
      }),
    }),
  decryptVaultString: (vaultPasswordId: number, ciphertext: string) =>
    request<{ plaintext: string }>("/vault/decrypt", {
      method: "POST",
      body: JSON.stringify({ vault_password_id: vaultPasswordId, ciphertext }),
    }),

  getGalaxyRequirements: () => request<{ content: string }>("/galaxy/requirements"),
  saveGalaxyRequirements: (content: string) =>
    request<{ content: string }>("/galaxy/requirements", {
      method: "PUT",
      body: JSON.stringify({ content }),
    }),
  getGalaxyInstalled: () => request<GalaxyInstalled>("/galaxy/installed"),
  listGalaxyInstalls: () => request<GalaxyInstall[]>("/galaxy/installs"),
  getGalaxyInstall: (id: number) => request<GalaxyInstallDetail>(`/galaxy/installs/${id}`),
  createGalaxyInstall: (upgrade: boolean) =>
    request<GalaxyInstallDetail>("/galaxy/installs", {
      method: "POST",
      body: JSON.stringify({ upgrade }),
    }),

  listRuns: () => request<Run[]>(scoped("/runs")),
  getRun: (id: number) => request<Run>(`/runs/${id}`),
  createRun: (payload: {
    playbook_id: number;
    inventory_id: number;
    group_id?: number | null;
    credential_id: number;
    vault_password_id?: number | null;
    become: boolean;
    check_mode: boolean;
    diff_mode: boolean;
    limit: string | null;
    extra_vars: Record<string, unknown> | null;
  }) => request<Run>("/runs", { method: "POST", body: JSON.stringify(payload) }),
};

export function runWebSocketUrl(runId: number): string {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${location.host}${API_BASE_URL}/runs/${runId}/ws`;
}
