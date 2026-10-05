import type {
  AdminUser,
  Credential,
  GitSource,
  InventoryDetail,
  InventoryRefresh,
  InventorySource,
  InventoryTargets,
  NotificationCatalog,
  NotificationChannel,
  PlaybookDetail,
  ProjectAccess,
  Run,
  RunTemplate,
  User,
  VaultPassword,
} from "@/lib/api";

export const NOW = "2026-10-05T12:00:00Z";

export const ALL_PERMISSIONS = [
  "content:read",
  "content:write",
  "secrets:list",
  "secrets:manage",
  "runs:trigger",
  "runs:become",
  "runs:read_extra_vars",
  "vault:encrypt",
  "vault:decrypt",
  "galaxy:manage",
  "users:manage",
  "audit:read",
  "workers:read",
  "projects:manage",
  "members:manage",
  "api_keys:manage",
  "sources:manage",
  "notifications:manage",
  "notifications:global",
];

export const VIEWER_PERMISSIONS = ["content:read"];

export function project(overrides: Partial<ProjectAccess> = {}): ProjectAccess {
  return { id: 1, name: "Default", role: "admin", permissions: ALL_PERMISSIONS, ...overrides };
}

export function adminUser(overrides: Partial<User> = {}): User {
  return {
    username: "admin",
    role: "admin",
    permissions: ALL_PERMISSIONS,
    projects: [project()],
    totp_enabled: false,
    ...overrides,
  };
}

export function viewerUser(overrides: Partial<User> = {}): User {
  return {
    username: "viewer",
    role: "viewer",
    permissions: VIEWER_PERMISSIONS,
    projects: [project({ role: "viewer", permissions: VIEWER_PERMISSIONS })],
    totp_enabled: false,
    ...overrides,
  };
}

export function playbook(overrides: Partial<PlaybookDetail> = {}): PlaybookDetail {
  return {
    id: 1,
    name: "site.yml",
    project_id: 1,
    created_at: NOW,
    updated_at: NOW,
    source_id: null,
    source_name: null,
    repo_path: null,
    commit: null,
    missing_at: null,
    content: "- hosts: all\n  tasks: []\n",
    ...overrides,
  };
}

export function inventory(overrides: Partial<InventoryDetail> = {}): InventoryDetail {
  return {
    id: 1,
    name: "lab",
    description: "The lab",
    project_id: 1,
    groups: [{ id: 1, name: "web" }],
    hosts: [{ id: 1, hostname: "web1.example", vars: { ansible_user: "deploy" }, group_ids: [1] }],
    ...overrides,
  };
}

export function targets(overrides: Partial<InventoryTargets> = {}): InventoryTargets {
  return {
    has_sources: false,
    hosts: 1,
    groups: [{ name: "web", hosts: 1, origin: "static" }],
    snapshot_id: null,
    snapshot_at: null,
    last_refresh: null,
    refresh_interval_seconds: 0,
    ...overrides,
  };
}

export function refresh(overrides: Partial<InventoryRefresh> = {}): InventoryRefresh {
  return {
    id: 1,
    status: "success",
    trigger: "manual",
    requested_by: "admin",
    queued_at: NOW,
    started_at: NOW,
    finished_at: NOW,
    worker_id: "w1",
    error: null,
    snapshot_id: 1,
    ...overrides,
  };
}

export function inventorySource(overrides: Partial<InventorySource> = {}): InventorySource {
  return {
    id: 1,
    inventory_id: 1,
    name: "netbox",
    plugin: "netbox.netbox.nb_inventory",
    config: "plugin: netbox.netbox.nb_inventory\napi_endpoint: https://netbox.example\n",
    credential_id: null,
    credential_name: null,
    enabled: true,
    position: 0,
    created_by: "admin",
    created_at: NOW,
    updated_at: NOW,
    ...overrides,
  };
}

export function credential(overrides: Partial<Credential> = {}): Credential {
  return {
    id: 1,
    name: "deploy-key",
    description: null,
    project_id: 1,
    created_at: NOW,
    kind: "ssh",
    env_names: null,
    store: "ansideck",
    store_path: null,
    store_key: null,
    store_location: null,
    ...overrides,
  };
}

export function vaultPassword(overrides: Partial<VaultPassword> = {}): VaultPassword {
  return {
    id: 1,
    name: "prod-vault",
    description: null,
    project_id: 1,
    created_at: NOW,
    store: "ansideck",
    store_path: null,
    store_key: null,
    store_location: null,
    ...overrides,
  };
}

export function run(overrides: Partial<Run> = {}): Run {
  return {
    id: 7,
    project_id: 1,
    playbook_id: 1,
    inventory_id: 1,
    credential_id: 1,
    vault_password_id: null,
    playbook_name: "site.yml",
    inventory_name: "lab",
    group_name: null,
    credential_name: "deploy-key",
    vault_password_name: null,
    become: false,
    check_mode: false,
    diff_mode: false,
    limit: null,
    extra_vars: null,
    status: "success",
    status_reason: null,
    timeout_seconds: 7200,
    cancel_requested_at: null,
    cancel_requested_by: null,
    triggered_by: "admin",
    return_code: 0,
    queued_at: NOW,
    claimed_at: NOW,
    started_at: NOW,
    finished_at: NOW,
    created_at: NOW,
    worker_id: "w1",
    attempt: 1,
    hosts_total: 1,
    hosts_ok: 1,
    hosts_changed: 0,
    hosts_failed: 0,
    hosts_unreachable: 0,
    waiting_reason: null,
    git_source_name: null,
    git_commit: null,
    playbook_path: null,
    commit_url: null,
    ...overrides,
  };
}

export function runTemplate(overrides: Partial<RunTemplate> = {}): RunTemplate {
  return {
    id: 3,
    project_id: 1,
    name: "Nightly patch",
    description: "Patches the lab every night",
    playbook_id: 1,
    playbook_name: "site.yml",
    inventory_id: 1,
    inventory_name: "lab",
    group_name: "web",
    credential_id: 1,
    credential_name: "deploy-key",
    vault_password_id: null,
    vault_password_name: null,
    become: false,
    check_mode: false,
    diff_mode: true,
    limit: null,
    extra_vars: { greeting: "hi" },
    timeout_seconds: 3600,
    missing: [],
    created_by: "admin",
    updated_by: "admin",
    created_at: NOW,
    updated_at: NOW,
    ...overrides,
  };
}

export function adminUserRow(overrides: Partial<AdminUser> = {}): AdminUser {
  return {
    id: 1,
    username: "admin",
    role: "admin",
    is_active: true,
    created_by: null,
    created_at: NOW,
    email: null,
    sso_linked: false,
    sso_provider: null,
    totp_enabled: false,
    ...overrides,
  };
}

export function gitSource(overrides: Partial<GitSource> = {}): GitSource {
  return {
    id: 1,
    project_id: 1,
    name: "infra",
    url: "https://git.example/infra.git",
    branch: "main",
    subdir: null,
    web_url: "https://git.example/infra",
    playbook_globs: ["*.yml"],
    auth_kind: "none",
    credential_id: null,
    credential_name: null,
    https_username: null,
    has_token: false,
    host_keys: [],
    auto_sync_seconds: 300,
    enabled: true,
    commit: "0123456789abcdef0123456789abcdef01234567",
    commit_subject: "Add site.yml",
    committed_at: NOW,
    warnings: [],
    playbooks: 2,
    missing_playbooks: 0,
    sync_requested_at: null,
    last_sync_started_at: NOW,
    last_sync_finished_at: NOW,
    last_sync_status: "ok",
    last_sync_error: null,
    created_by: "admin",
    created_at: NOW,
    ...overrides,
  };
}

export const CATALOG: NotificationCatalog = {
  events: [
    { name: "run.failed", label: "Run failed", description: "A run failed", project: true, group: "Runs" },
    { name: "run.recovered", label: "Run recovered", description: "Back to green", project: true, group: "Runs" },
    { name: "worker.offline", label: "Worker offline", description: "No heartbeat", project: false, group: "Operations" },
  ],
  kinds: ["webhook", "discord", "slack", "teams", "email", "pushbullet", "pushover"],
  email_available: true,
};

export function channel(overrides: Partial<NotificationChannel> = {}): NotificationChannel {
  return {
    id: 1,
    project_id: null,
    name: "ops-discord",
    kind: "discord",
    target: "https://discord.com/…abcd",
    recipients: null,
    has_secret: false,
    events: ["run.failed"],
    enabled: true,
    created_by: "admin",
    created_at: NOW,
    updated_at: NOW,
    last_delivery: { status: "sent", event: "run.failed", created_at: NOW, error: null },
    ...overrides,
  };
}
