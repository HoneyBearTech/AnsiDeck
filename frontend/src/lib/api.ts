const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
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

export interface User {
  username: string;
}

export interface PlaybookSummary {
  id: number;
  name: string;
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
  created_at: string;
}

export interface Run {
  id: number;
  playbook_name: string;
  inventory_name: string;
  group_name: string | null;
  credential_name: string;
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
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),

  listPlaybooks: () => request<PlaybookSummary[]>("/playbooks"),
  getPlaybook: (id: number) => request<PlaybookDetail>(`/playbooks/${id}`),
  createPlaybook: (name: string, content: string) =>
    request<PlaybookDetail>("/playbooks", { method: "POST", body: JSON.stringify({ name, content }) }),
  updatePlaybook: (id: number, payload: { name?: string; content?: string }) =>
    request<PlaybookDetail>(`/playbooks/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
  deletePlaybook: (id: number) => request<void>(`/playbooks/${id}`, { method: "DELETE" }),

  listInventories: () => request<InventorySummary[]>("/inventories"),
  getInventory: (id: number) => request<InventoryDetail>(`/inventories/${id}`),
  createInventory: (name: string, description?: string) =>
    request<InventoryDetail>("/inventories", {
      method: "POST",
      body: JSON.stringify({ name, description }),
    }),
  updateInventory: (id: number, payload: { name?: string; description?: string }) =>
    request<InventoryDetail>(`/inventories/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
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
    request<void>(`/inventories/${inventoryId}/groups/${groupId}`, { method: "DELETE" }),

  createHost: (
    inventoryId: number,
    payload: { hostname: string; vars?: Record<string, unknown>; group_ids?: number[] },
  ) =>
    request<InventoryHost>(`/inventories/${inventoryId}/hosts`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateHost: (
    inventoryId: number,
    hostId: number,
    payload: { hostname?: string; vars?: Record<string, unknown>; group_ids?: number[] },
  ) =>
    request<InventoryHost>(`/inventories/${inventoryId}/hosts/${hostId}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  deleteHost: (inventoryId: number, hostId: number) =>
    request<void>(`/inventories/${inventoryId}/hosts/${hostId}`, { method: "DELETE" }),

  listCredentials: () => request<Credential[]>("/credentials"),
  createCredential: (name: string, privateKey: string, description?: string) =>
    request<Credential>("/credentials", {
      method: "POST",
      body: JSON.stringify({ name, description, private_key: privateKey }),
    }),
  deleteCredential: (id: number) => request<void>(`/credentials/${id}`, { method: "DELETE" }),

  listRuns: () => request<Run[]>("/runs"),
  getRun: (id: number) => request<Run>(`/runs/${id}`),
  createRun: (payload: {
    playbook_id: number;
    inventory_id: number;
    group_id?: number | null;
    credential_id: number;
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
