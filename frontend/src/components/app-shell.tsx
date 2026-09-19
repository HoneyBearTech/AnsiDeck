import { NavLink, Outlet } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/context/auth-context";
import { cn } from "@/lib/utils";

function NavItem({
  to,
  label,
  permission,
  visible = true,
}: {
  to: string;
  label: string;
  permission?: string;
  visible?: boolean;
}) {
  const { can } = useAuth();
  if (!visible || (permission && !can(permission))) return null;

  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cn(
          "text-sm text-muted-foreground transition-colors duration-150 hover:text-foreground",
          isActive && "text-primary",
        )
      }
    >
      {label}
    </NavLink>
  );
}

const ALL_PROJECTS = "__all__";

function ProjectSwitcher() {
  const { user, activeProjectId, setActiveProject } = useAuth();
  if (!user || user.projects.length === 0) return null;

  const isAdmin = user.role === "admin";
  if (!isAdmin && user.projects.length === 1) {
    return <span className="text-sm text-muted-foreground">{user.projects[0].name}</span>;
  }

  return (
    <Select
      value={activeProjectId === null ? ALL_PROJECTS : String(activeProjectId)}
      onValueChange={(value) => setActiveProject(value === ALL_PROJECTS ? null : Number(value))}
    >
      <SelectTrigger className="h-8 w-44 text-sm" aria-label="Active project">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {isAdmin && <SelectItem value={ALL_PROJECTS}>All projects</SelectItem>}
        {user.projects.map((project) => (
          <SelectItem key={project.id} value={String(project.id)}>
            {project.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function AppShell() {
  const { user, logout, activeProject, activeProjectId } = useAuth();
  const isAdmin = user?.role === "admin";
  const hasNoProject = !!user && !isAdmin && user.projects.length === 0;
  const canSeeProjects = isAdmin || !!user?.projects.some((p) => p.role === "admin");

  return (
    <div className="min-h-screen bg-background">
      <header className="flex items-center justify-between border-b border-border px-6 py-4">
        <div className="flex items-center gap-6">
          <span className="font-mono text-lg text-primary">AnsiDeck</span>
          <nav className="flex items-center gap-4">
            <NavItem to="/" label="Dashboard" />
            <NavItem to="/playbooks" label="Playbooks" />
            <NavItem to="/inventories" label="Inventories" />
            <NavItem to="/credentials" label="Credentials" permission="secrets:list" />
            <NavItem to="/galaxy" label="Galaxy" />
            <NavItem to="/vault" label="Vault" permission="secrets:list" />
            <NavItem to="/runs" label="Runs" />
            <NavItem to="/projects" label="Projects" visible={canSeeProjects} />
            <NavItem to="/users" label="Users" permission="users:manage" />
            <NavItem to="/audit" label="Audit" permission="audit:read" />
          </nav>
        </div>
        <div className="flex items-center gap-3">
          <ProjectSwitcher />
          <span className="text-sm text-muted-foreground">
            {user?.username} · {isAdmin ? "admin" : (activeProject?.role ?? "no project")}
          </span>
          <Button variant="outline" size="sm" onClick={() => logout()}>
            Log out
          </Button>
        </div>
      </header>
      <main className="mx-auto max-w-5xl p-8">
        {hasNoProject ? (
          <div className="flex flex-col gap-2">
            <h1 className="text-xl font-semibold">No project yet</h1>
            <p className="text-sm text-muted-foreground">
              You're not a member of any project, so there's nothing to show. Ask an admin to add you to one.
            </p>
          </div>
        ) : (
          // Re-key on the active project so every page reloads its data when it changes.
          <Outlet key={activeProjectId ?? "all"} />
        )}
      </main>
    </div>
  );
}
