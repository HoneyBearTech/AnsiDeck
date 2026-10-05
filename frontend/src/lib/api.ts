const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

export const SSO_LOGIN_URL = `${API_BASE_URL}/auth/oidc/login`;
export const GITHUB_LOGIN_URL = `${API_BASE_URL}/auth/github/login`;

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
  totp_enabled: boolean;
}

// The password was right; the login finishes with loginMfa().
export interface MfaChallenge {
  mfa_required: true;
}

export interface TotpSetup {
  secret: string;
  otpauth_uri: string;
  qr: string; // SVG data URI, for an <img>
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

export type ApiKeyPreset = "trigger" | "read-only";

export interface ApiKey {
  id: number;
  name: string;
  preset: ApiKeyPreset;
  prefix: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  last_used_ip: string | null;
  revoked_at: string | null;
  status: "active" | "expired" | "revoked";
}

// The plaintext token only ever exists in this creation response.
export interface ApiKeyCreated extends ApiKey {
  token: string;
}

export interface AdminUser {
  id: number;
  username: string;
  role: "admin" | "operator" | "viewer";
  is_active: boolean;
  created_by: string | null;
  created_at: string;
  email: string | null;
  sso_linked: boolean;
  sso_provider: string | null;
  totp_enabled: boolean;
}

export interface AuthProviders {
  oidc: { enabled: boolean; label: string };
  github: { enabled: boolean; label: string };
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
  // Synced from git (read-only): its source, path in the repository and current commit; set
  // missing_at once the file is gone upstream (it can't run then, and may be deleted).
  source_id: number | null;
  source_name: string | null;
  repo_path: string | null;
  commit: string | null;
  missing_at: string | null;
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

/** A dynamic inventory source: an inventory plugin's config, refreshed in a worker. */
export interface InventorySource {
  id: number;
  inventory_id: number;
  name: string;
  plugin: string;
  config: string;
  credential_id: number | null;
  credential_name: string | null;
  enabled: boolean;
  position: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface InventorySourceInput {
  name: string;
  config: string;
  credential_id: number | null;
  enabled: boolean;
}

export type RefreshStatus = "queued" | "running" | "success" | "failed" | "timed_out";

export interface InventoryRefresh {
  id: number;
  status: RefreshStatus;
  trigger: "manual" | "schedule" | "sources_changed" | "static_changed";
  requested_by: string | null;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  worker_id: string | null;
  error: string | null;
  snapshot_id: number | null;
}

export interface InventorySnapshot {
  id: number;
  created_at: string;
  refresh_id: number | null;
  host_count: number;
  group_count: number;
  warnings: string[];
  sources: { id: number; name: string; plugin: string }[];
  vars: Record<string, unknown>;
  groups: { name: string; hosts: number; children: string[]; vars: Record<string, unknown> }[];
}

export type HostOrigin = "static" | "source" | "both";

export interface MergedHost {
  name: string;
  origin: HostOrigin;
  groups: string[];
  vars: Record<string, unknown>;
  // Keys whose source value the inventory's own vars replace.
  overridden: string[];
}

export interface InventoryTargets {
  has_sources: boolean;
  hosts: number;
  groups: { name: string; hosts: number; origin: HostOrigin }[];
  snapshot_id: number | null;
  snapshot_at: string | null;
  last_refresh: InventoryRefresh | null;
  refresh_interval_seconds: number;
}

// Where a credential's key or a vault password lives: encrypted in AnsiDeck, or a reference
// into the secret store (OpenBao / Vault), read when a run starts.
export interface SecretRef {
  store: "ansideck" | "external";
  store_path: string | null;
  store_key: string | null;
  store_location: string | null;
}

export type CredentialKind = "ssh" | "env";

export interface Credential extends SecretRef {
  id: number;
  name: string;
  description: string | null;
  project_id: number;
  created_at: string;
  // "ssh": a private key (runs, git deploy keys); "env": named variables for inventory plugins.
  kind: CredentialKind;
  // An env credential's variable names (never values); null when they live in the store.
  env_names: string[] | null;
}

/** An env credential's variables: entered here, or every key of one secret in the store. */
export type EnvSource =
  { kind: "ansideck"; env: Record<string, string> } | { kind: "external"; path: string };

export interface VaultPassword extends SecretRef {
  id: number;
  name: string;
  description: string | null;
  project_id: number;
  created_at: string;
}

export interface SecretCheck {
  ok: boolean;
  version: number | null;
  env_names?: string[] | null;
  error_kind: string | null;
  error: string | null;
}

export interface SecretStoreInfo {
  enabled: boolean;
  label: string;
  base_path: string | null;
  path_rules: string;
}

export interface SecretStoreStatus {
  enabled: boolean;
  label: string;
  url: string | null;
  ok: boolean | null;
  reachable: boolean | null;
  sealed: boolean | null;
  version: string | null;
  token_ttl: number | null;
  error_kind: string | null;
  error: string | null;
  checked_at: number | null;
  last_ok_at: number | null;
}

/** Either the secret itself, or a reference into the secret store. */
export type SecretSource =
  { kind: "ansideck"; value: string } | { kind: "external"; path: string; key: string };

export interface VaultEncryptResult {
  vault_text: string;
  yaml_block: string;
}

export interface GalaxyInstall {
  id: number;
  status: "queued" | "running" | "success" | "failed";
  status_reason: string | null;
  triggered_by: string;
  upgrade: boolean;
  return_code: number | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  // A queued install starts once the runs running now have finished; null unless queued.
  waiting_for_runs: number | null;
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
  status: "queued" | "running" | "success" | "failed" | "cancelled" | "timed_out";
  // Why it ended the way it did when that wasn't ansible's own result (worker lost, timed out, ...).
  status_reason: string | null;
  timeout_seconds: number;
  cancel_requested_at: string | null;
  cancel_requested_by: string | null;
  triggered_by: string;
  return_code: number | null;
  queued_at: string;
  claimed_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  worker_id: string | null;
  attempt: number;
  hosts_total: number | null;
  hosts_ok: number | null;
  hosts_changed: number | null;
  hosts_failed: number | null;
  hosts_unreachable: number | null;
  // Why a queued run hasn't started (getRun only; null otherwise).
  waiting_reason: string | null;
  // Runs of playbooks synced from git: the commit they execute and a link to it.
  git_source_name: string | null;
  git_commit: string | null;
  playbook_path: string | null;
  commit_url: string | null;
}

export type GitAuthKind = "none" | "ssh_key" | "https_token";

export interface GitSource {
  id: number;
  project_id: number;
  name: string;
  url: string;
  branch: string;
  subdir: string | null;
  web_url: string | null;
  playbook_globs: string[];
  auth_kind: GitAuthKind;
  credential_id: number | null;
  credential_name: string | null;
  https_username: string | null;
  has_token: boolean;
  host_keys: { type: string; fingerprint: string }[];
  auto_sync_seconds: number;
  enabled: boolean;
  commit: string | null;
  commit_subject: string | null;
  committed_at: string | null;
  warnings: string[];
  playbooks: number;
  missing_playbooks: number;
  sync_requested_at: string | null;
  last_sync_started_at: string | null;
  last_sync_finished_at: string | null;
  last_sync_status: "ok" | "failed" | "running" | null;
  last_sync_error: string | null;
  created_by: string;
  created_at: string;
}

export interface GitSourceInput {
  name?: string;
  url?: string;
  branch?: string;
  subdir?: string | null;
  web_url?: string | null;
  playbook_globs?: string[];
  auth_kind?: GitAuthKind;
  credential_id?: number | null;
  https_username?: string | null;
  token?: string; // write-only; omit to keep the stored one
  auto_sync_seconds?: number;
  enabled?: boolean;
}

export interface GitTestResult {
  ok: boolean;
  error: string | null;
  default_branch: string | null;
  branch_exists: boolean | null;
  host_keys: { type: string; fingerprint: string; trusted: boolean }[];
  host_key_trusted: boolean | null;
}

export interface WorkerInfo {
  id: string;
  slots: number;
  // Whether its playbooks run as per-slot users; null: a worker too old to say.
  isolated: boolean | null;
  running: number;
  online: boolean;
  first_seen_at: string;
  last_seen_at: string;
}

export type ChannelKind = "webhook" | "discord" | "slack" | "teams" | "email" | "pushbullet" | "pushover";

export interface NotificationEvent {
  name: string;
  label: string;
  description: string;
  // Available to project channels (global channels can take every event).
  project: boolean;
  group: string; // Runs, Operations, Security
}

export interface NotificationCatalog {
  events: NotificationEvent[];
  kinds: ChannelKind[];
  email_available: boolean;
}

export interface NotificationChannel {
  id: number;
  project_id: number | null;
  name: string;
  kind: ChannelKind;
  // Safe to show: scheme://host/…last 4, the email addresses, or the push service's name.
  target: string;
  recipients: string[] | null;
  has_secret: boolean;
  events: string[];
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
  last_delivery: { status: string; event: string; created_at: string; error: string | null } | null;
}

// Write-only settings; on update, leave a field out to keep what is stored.
export interface ChannelSecrets {
  url?: string;
  secret?: string; // "" removes the webhook signing secret
  token?: string;
  user_key?: string;
  recipients?: string[];
}

export interface ChannelInput extends ChannelSecrets {
  name: string;
  kind: ChannelKind;
  events: string[];
  enabled?: boolean;
}

export interface ChannelUpdate extends ChannelSecrets {
  name?: string;
  events?: string[];
  enabled?: boolean;
}

export interface NotificationDelivery {
  id: number;
  event: string;
  title: string;
  status: "pending" | "sending" | "sent" | "failed";
  attempts: number;
  last_status_code: number | null;
  last_error: string | null;
  created_at: string;
  next_attempt_at: string | null;
  sent_at: string | null;
}

export interface TestResult {
  ok: boolean;
  status_code: number | null;
  error: string | null;
}

// null = global channels.
function channelsPath(projectId: number | null): string {
  return projectId === null ? "/notifications/channels" : `/projects/${projectId}/notifications/channels`;
}

export const api = {
  health: () => request<HealthStatus>("/health"),
  login: (username: string, password: string) =>
    request<User | MfaChallenge>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  loginMfa: (second: { code: string } | { recovery_code: string }) =>
    request<User>("/auth/login/mfa", { method: "POST", body: JSON.stringify(second) }),
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
  totpSetup: (currentPassword: string) =>
    request<TotpSetup>("/auth/totp/setup", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword }),
    }),
  totpEnable: (code: string) =>
    request<{ recovery_codes: string[] }>("/auth/totp/enable", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),
  totpDisable: (currentPassword: string, code: string) =>
    request<{ ok: boolean }>("/auth/totp/disable", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, code }),
    }),
  totpRegenerateRecoveryCodes: (currentPassword: string) =>
    request<{ recovery_codes: string[] }>("/auth/totp/recovery-codes", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword }),
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

  listApiKeys: (projectId: number) => request<ApiKey[]>(`/projects/${projectId}/api-keys`),
  createApiKey: (projectId: number, name: string, preset: ApiKeyPreset, expiresInDays: number) =>
    request<ApiKeyCreated>(`/projects/${projectId}/api-keys`, {
      method: "POST",
      body: JSON.stringify({ name, preset, expires_in_days: expiresInDays }),
    }),
  revokeApiKey: (projectId: number, keyId: number) =>
    request<void>(`/projects/${projectId}/api-keys/${keyId}`, { method: "DELETE" }),

  listUsers: () => request<AdminUser[]>("/users"),
  createUser: (
    username: string,
    password: string,
    role: AdminUser["role"],
    projectId?: number | null,
    email?: string | null,
  ) =>
    request<AdminUser>("/users", {
      method: "POST",
      body: JSON.stringify({
        username,
        password,
        role,
        project_id: projectId ?? undefined,
        email: email || undefined,
      }),
    }),
  updateUser: (
    id: number,
    payload: {
      role?: AdminUser["role"];
      is_active?: boolean;
      password?: string;
      email?: string | null;
    },
  ) =>
    request<AdminUser>(`/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteUser: (id: number) => request<void>(`/users/${id}`, { method: "DELETE" }),
  unlinkSso: (id: number) => request<void>(`/users/${id}/sso-link`, { method: "DELETE" }),
  resetUserTotp: (id: number) => request<void>(`/users/${id}/totp`, { method: "DELETE" }),

  getAuthProviders: () => request<AuthProviders>("/auth/providers"),

  listAudit: (params: {
    limit: number;
    offset: number;
    action?: string | undefined;
    actor?: string | undefined;
    outcome?: string | undefined;
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

  listInventorySources: (id: number) => request<InventorySource[]>(`/inventories/${id}/sources`),
  createInventorySource: (id: number, input: InventorySourceInput) =>
    request<InventorySource>(`/inventories/${id}/sources`, {
      method: "POST",
      body: JSON.stringify(input),
    }),
  updateInventorySource: (id: number, sourceId: number, input: Partial<InventorySourceInput>) =>
    request<InventorySource>(`/inventories/${id}/sources/${sourceId}`, {
      method: "PATCH",
      body: JSON.stringify(input),
    }),
  deleteInventorySource: (id: number, sourceId: number) =>
    request<void>(`/inventories/${id}/sources/${sourceId}`, { method: "DELETE" }),
  refreshInventory: (id: number) =>
    request<InventoryRefresh | null>(`/inventories/${id}/refresh`, { method: "POST" }),
  listInventoryRefreshes: (id: number, limit = 10) =>
    request<InventoryRefresh[]>(`/inventories/${id}/refreshes?limit=${limit}`),
  getInventorySnapshot: (id: number) => request<InventorySnapshot | null>(`/inventories/${id}/snapshot`),
  inventoryHosts: (id: number, q: string, page = 1) =>
    request<{ total: number; hosts: MergedHost[] }>(
      `/inventories/${id}/hosts?page=${page}${q ? `&q=${encodeURIComponent(q)}` : ""}`,
    ),
  inventoryTargets: (id: number) => request<InventoryTargets>(`/inventories/${id}/targets`),
  setInventoryRefreshInterval: (id: number, seconds: number) =>
    request<InventoryTargets>(`/inventories/${id}/refresh-settings`, {
      method: "PUT",
      body: JSON.stringify({ refresh_interval_seconds: seconds }),
    }),

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

  listCredentials: (kind?: CredentialKind) => {
    const query = new URLSearchParams();
    if (activeProjectId !== null) query.set("project_id", String(activeProjectId));
    if (kind) query.set("kind", kind);
    return request<Credential[]>(`/credentials${query.size ? `?${query}` : ""}`);
  },
  createEnvCredential: (name: string, source: EnvSource, description?: string) =>
    request<Credential>("/credentials", {
      method: "POST",
      body: JSON.stringify({
        name,
        description,
        kind: "env",
        ...(source.kind === "ansideck" ? { env: source.env } : { store_path: source.path }),
        project_id: activeProjectId ?? undefined,
      }),
    }),
  createCredential: (name: string, source: SecretSource, description?: string) =>
    request<Credential>("/credentials", {
      method: "POST",
      body: JSON.stringify({
        name,
        description,
        ...(source.kind === "ansideck"
          ? { private_key: source.value }
          : { store_path: source.path, store_key: source.key }),
        project_id: activeProjectId ?? undefined,
      }),
    }),
  checkCredential: (id: number) => request<SecretCheck>(`/credentials/${id}/check`, { method: "POST" }),
  deleteCredential: (id: number) => request<void>(`/credentials/${id}`, { method: "DELETE" }),

  listVaultPasswords: () => request<VaultPassword[]>(scoped("/vault-passwords")),
  createVaultPassword: (name: string, source: SecretSource, description?: string) =>
    request<VaultPassword>("/vault-passwords", {
      method: "POST",
      body: JSON.stringify({
        name,
        description,
        ...(source.kind === "ansideck"
          ? { password: source.value }
          : { store_path: source.path, store_key: source.key }),
        project_id: activeProjectId ?? undefined,
      }),
    }),
  deleteVaultPassword: (id: number) => request<void>(`/vault-passwords/${id}`, { method: "DELETE" }),
  checkVaultPassword: (id: number) =>
    request<SecretCheck>(`/vault-passwords/${id}/check`, { method: "POST" }),
  secretStoreInfo: (projectId: number) =>
    request<SecretStoreInfo>(`/secret-store/info?project_id=${projectId}`),
  secretStoreStatus: () => request<SecretStoreStatus>("/secret-store/status"),
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
    group_name?: string | null;
    credential_id: number;
    vault_password_id?: number | null;
    become: boolean;
    check_mode: boolean;
    diff_mode: boolean;
    limit: string | null;
    extra_vars: Record<string, unknown> | null;
    timeout_seconds?: number;
  }) => request<Run>("/runs", { method: "POST", body: JSON.stringify(payload) }),
  cancelRun: (id: number) => request<Run>(`/runs/${id}/cancel`, { method: "POST" }),

  listWorkers: () => request<WorkerInfo[]>("/workers"),

  listGitSources: (projectId: number) => request<GitSource[]>(`/projects/${projectId}/git-sources`),
  createGitSource: (projectId: number, input: GitSourceInput) =>
    request<GitSource>(`/projects/${projectId}/git-sources`, {
      method: "POST",
      body: JSON.stringify(input),
    }),
  updateGitSource: (projectId: number, id: number, input: GitSourceInput) =>
    request<GitSource>(`/projects/${projectId}/git-sources/${id}`, {
      method: "PATCH",
      body: JSON.stringify(input),
    }),
  deleteGitSource: (projectId: number, id: number) =>
    request<void>(`/projects/${projectId}/git-sources/${id}`, { method: "DELETE" }),
  testGitSource: (projectId: number, id: number) =>
    request<GitTestResult>(`/projects/${projectId}/git-sources/${id}/test`, { method: "POST" }),
  trustGitHostKey: (projectId: number, id: number, trust: { fingerprint?: string; known_hosts?: string }) =>
    request<GitSource>(`/projects/${projectId}/git-sources/${id}/trust-host-key`, {
      method: "POST",
      body: JSON.stringify(trust),
    }),
  syncGitSource: (projectId: number, id: number) =>
    request<{ queued: boolean }>(`/projects/${projectId}/git-sources/${id}/sync`, { method: "POST" }),

  notificationCatalog: () => request<NotificationCatalog>("/notifications/catalog"),
  listChannels: (projectId: number | null) => request<NotificationChannel[]>(channelsPath(projectId)),
  createChannel: (projectId: number | null, input: ChannelInput) =>
    request<NotificationChannel>(channelsPath(projectId), { method: "POST", body: JSON.stringify(input) }),
  updateChannel: (projectId: number | null, id: number, update: ChannelUpdate) =>
    request<NotificationChannel>(`${channelsPath(projectId)}/${id}`, {
      method: "PATCH",
      body: JSON.stringify(update),
    }),
  deleteChannel: (projectId: number | null, id: number) =>
    request<void>(`${channelsPath(projectId)}/${id}`, { method: "DELETE" }),
  testChannel: (projectId: number | null, id: number) =>
    request<TestResult>(`${channelsPath(projectId)}/${id}/test`, { method: "POST" }),
  listDeliveries: (projectId: number | null, id: number) =>
    request<NotificationDelivery[]>(`${channelsPath(projectId)}/${id}/deliveries`),
};

/** `from` skips the log lines already received, so a dropped stream resumes where it left off. */
export function runWebSocketUrl(runId: number, from = 0): string {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${location.host}${API_BASE_URL}/runs/${runId}/ws?from=${from}`;
}
