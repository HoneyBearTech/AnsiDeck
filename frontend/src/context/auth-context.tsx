import * as React from "react";

import { api, setApiActiveProject, type ProjectAccess, type User } from "@/lib/api";

// Permissions that never depend on a project (mirrors the backend's GLOBAL_ONLY).
const GLOBAL_PERMISSIONS = new Set(["users:manage", "audit:read", "galaxy:manage", "projects:manage"]);
const STORAGE_KEY = "ansideck.activeProject";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  // Resolves to "mfa" when the account needs a second factor (then call completeMfa).
  login: (username: string, password: string) => Promise<"ok" | "mfa">;
  completeMfa: (second: { code: string } | { recovery_code: string }) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  // Permission in the active project (or globally for global-only permissions).
  can: (permission: string) => boolean;
  // Permission in one specific project.
  canInProject: (projectId: number, permission: string) => boolean;
  // null = "all projects" (global admins only).
  activeProjectId: number | null;
  activeProject: ProjectAccess | null;
  setActiveProject: (projectId: number | null) => void;
}

const AuthContext = React.createContext<AuthContextValue | null>(null);

function readStoredChoice(): number | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw && raw !== "all" ? Number(raw) : null;
  } catch {
    return null;
  }
}

function resolveActiveProject(user: User | null, choice: number | null): number | null {
  if (!user) return null;
  if (choice !== null && user.projects.some((p) => p.id === choice)) return choice;
  // A global admin may work across all projects; everyone else needs a concrete one.
  return user.role === "admin" ? null : (user.projects[0]?.id ?? null);
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = React.useState<User | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [choice, setChoice] = React.useState<number | null>(readStoredChoice);

  const activeProjectId = resolveActiveProject(user, choice);

  // Layout effects run before the passive effects pages use to fetch data, so the
  // API layer knows the active project by the time a (re-keyed) page loads.
  React.useLayoutEffect(() => {
    setApiActiveProject(activeProjectId);
  }, [activeProjectId]);

  React.useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = React.useCallback(async (username: string, password: string) => {
    const result = await api.login(username, password);
    if ("mfa_required" in result) return "mfa";
    setUser(result);
    return "ok";
  }, []);

  const completeMfa = React.useCallback(async (second: { code: string } | { recovery_code: string }) => {
    setUser(await api.loginMfa(second));
  }, []);

  const logout = React.useCallback(async () => {
    await api.logout();
    setUser(null);
  }, []);

  const refreshUser = React.useCallback(async () => {
    setUser(await api.me());
  }, []);

  const setActiveProject = React.useCallback((projectId: number | null) => {
    setChoice(projectId);
    try {
      localStorage.setItem(STORAGE_KEY, projectId === null ? "all" : String(projectId));
    } catch {
      // storage unavailable: the choice just won't persist
    }
  }, []);

  const activeProject = user?.projects.find((p) => p.id === activeProjectId) ?? null;

  const can = React.useCallback(
    (permission: string) => {
      if (!user) return false;
      if (GLOBAL_PERMISSIONS.has(permission) || !activeProject) {
        return user.permissions.includes(permission);
      }
      return activeProject.permissions.includes(permission);
    },
    [user, activeProject],
  );

  const canInProject = React.useCallback(
    (projectId: number, permission: string) => {
      if (!user) return false;
      if (GLOBAL_PERMISSIONS.has(permission)) return user.permissions.includes(permission);
      if (user.role === "admin") return true;
      return user.projects.find((p) => p.id === projectId)?.permissions.includes(permission) ?? false;
    },
    [user],
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        completeMfa,
        logout,
        refreshUser,
        can,
        canInProject,
        activeProjectId,
        activeProject,
        setActiveProject,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
