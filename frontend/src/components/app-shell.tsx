import { ChevronDown, Menu, X } from "lucide-react";
import * as React from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/context/auth-context";
import { cn } from "@/lib/utils";

interface NavEntry {
  to: string;
  label: string;
}

const linkClass = ({ isActive }: { isActive: boolean }) =>
  cn(
    "text-sm text-muted-foreground transition-colors duration-150 hover:text-foreground",
    isActive && "text-primary",
  );
// In the phone/tablet menu every link gets a finger-sized hit area.
const menuLinkClass = (state: { isActive: boolean }) => cn(linkClass(state), "block py-2 pointer-coarse:py-3");

/** The links this person may use, split into everyday pages and administration. */
function useNavEntries(): { main: NavEntry[]; admin: NavEntry[] } {
  const { user, can } = useAuth();
  const isAdmin = user?.role === "admin";
  const canSeeProjects = isAdmin || !!user?.projects.some((p) => p.role === "admin");
  const canSeeNotifications =
    isAdmin || !!user?.projects.some((p) => p.permissions.includes("notifications:manage"));
  const main: (NavEntry & { show?: boolean })[] = [
    { to: "/", label: "Dashboard" },
    { to: "/playbooks", label: "Playbooks" },
    { to: "/inventories", label: "Inventories" },
    { to: "/runs", label: "Runs" },
    { to: "/templates", label: "Templates" },
    { to: "/credentials", label: "Credentials", show: can("secrets:list") },
    { to: "/vault", label: "Vault", show: can("secrets:list") },
    { to: "/galaxy", label: "Galaxy" },
  ];
  const admin: (NavEntry & { show?: boolean })[] = [
    { to: "/projects", label: "Projects", show: canSeeProjects },
    { to: "/users", label: "Users", show: can("users:manage") },
    { to: "/audit", label: "Audit log", show: can("audit:read") },
    { to: "/workers", label: "Workers", show: can("workers:read") },
    { to: "/notifications", label: "Notifications", show: canSeeNotifications },
  ];
  return {
    main: main.filter((e) => e.show !== false),
    admin: admin.filter((e) => e.show !== false),
  };
}

const ALL_PROJECTS = "__all__";

function ProjectSwitcher({ className }: { className?: string }) {
  const { user, activeProjectId, setActiveProject } = useAuth();
  if (!user || user.projects.length === 0) return null;

  const isAdmin = user.role === "admin";
  if (!isAdmin && user.projects.length === 1) {
    return <span className={cn("text-sm text-muted-foreground", className)}>{user.projects[0]?.name}</span>;
  }

  return (
    <Select
      value={activeProjectId === null ? ALL_PROJECTS : String(activeProjectId)}
      onValueChange={(value) => setActiveProject(value === ALL_PROJECTS ? null : Number(value))}
    >
      <SelectTrigger className={cn("h-8 w-40 text-sm", className)} aria-label="Active project">
        <span className="min-w-0 truncate">
          <SelectValue />
        </span>
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

function roleLabel(user: ReturnType<typeof useAuth>["user"], projectRole: string | undefined): string {
  if (user?.role === "admin") return "global admin";
  return projectRole ?? "no project";
}

function AdminMenu({ entries }: { entries: NavEntry[] }) {
  const location = useLocation();
  const navigate = useNavigate();
  const active = entries.some((e) => location.pathname.startsWith(e.to));
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className={cn(
          "flex items-center gap-1 rounded-sm text-sm text-muted-foreground transition-colors duration-150 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          active && "text-primary",
        )}
      >
        Admin
        <ChevronDown aria-hidden="true" className="size-3.5" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        {entries.map((entry) => (
          <DropdownMenuItem key={entry.to} onSelect={() => navigate(entry.to)}>
            {entry.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function UserMenu() {
  const { user, logout, activeProject } = useAuth();
  const navigate = useNavigate();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="gap-1 text-muted-foreground hover:text-foreground">
          {user?.username}
          <ChevronDown aria-hidden="true" className="size-3.5" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>
          Signed in as <span className="text-foreground">{user?.username}</span> ({roleLabel(user, activeProject?.role)})
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => navigate("/account")}>Account</DropdownMenuItem>
        <DropdownMenuItem onSelect={() => logout()}>Log out</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** The menu below wide-desktop width (1280 px): every link, the project, the account and logging out. */
function MobileMenu({ main, admin, onClose }: { main: NavEntry[]; admin: NavEntry[]; onClose: () => void }) {
  const { user, logout, activeProject } = useAuth();
  return (
    <nav id="mobile-menu" aria-label="Main" className="flex flex-col gap-4 border-t border-border py-4 xl:hidden">
      <ProjectSwitcher className="w-full sm:hidden" />
      <ul className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3">
        {main.map((entry) => (
          <li key={entry.to}>
            <NavLink to={entry.to} end={entry.to === "/"} className={menuLinkClass} onClick={onClose}>
              {entry.label}
            </NavLink>
          </li>
        ))}
      </ul>
      {admin.length > 0 && (
        <div className="flex flex-col gap-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Admin</p>
          <ul className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3">
            {admin.map((entry) => (
              <li key={entry.to}>
                <NavLink to={entry.to} className={menuLinkClass} onClick={onClose}>
                  {entry.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
        <span className="text-sm text-muted-foreground">
          {user?.username} ({roleLabel(user, activeProject?.role)})
        </span>
        <NavLink to="/account" className={menuLinkClass} onClick={onClose}>
          Account
        </NavLink>
        <Button variant="outline" size="sm" onClick={() => logout()}>
          Log out
        </Button>
      </div>
    </nav>
  );
}

export function AppShell() {
  const { user, activeProjectId } = useAuth();
  const { main, admin } = useNavEntries();
  const [menuOpen, setMenuOpen] = React.useState(false);
  const isAdmin = user?.role === "admin";
  const hasNoProject = !!user && !isAdmin && user.projects.length === 0;

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border">
        <div className="mx-auto max-w-6xl px-4 sm:px-8">
          <div className="flex h-14 items-center gap-6">
            <Link to="/" className="font-mono text-lg text-primary">
              AnsiDeck
            </Link>
            <nav aria-label="Main" className="hidden items-center gap-x-4 xl:flex">
              {main.map((entry) => (
                <NavLink key={entry.to} to={entry.to} end={entry.to === "/"} className={linkClass}>
                  {entry.label}
                </NavLink>
              ))}
              {admin.length > 0 && <AdminMenu entries={admin} />}
            </nav>
            <div className="ml-auto flex items-center gap-2">
              <ProjectSwitcher className="hidden sm:flex" />
              <div className="hidden xl:block">
                <UserMenu />
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="xl:hidden"
                aria-expanded={menuOpen}
                aria-controls="mobile-menu"
                aria-label={menuOpen ? "Close menu" : "Open menu"}
                onClick={() => setMenuOpen((open) => !open)}
              >
                {menuOpen ? <X aria-hidden="true" className="size-5" /> : <Menu aria-hidden="true" className="size-5" />}
              </Button>
            </div>
          </div>
          {menuOpen && <MobileMenu main={main} admin={admin} onClose={() => setMenuOpen(false)} />}
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6 sm:p-8">
        {hasNoProject ? (
          <div className="flex flex-col gap-2">
            <h1 className="text-xl font-semibold">No project yet</h1>
            <p className="text-sm text-muted-foreground">
              You're not a member of any project, so there's nothing to show. Ask an admin to add you to one.
            </p>
          </div>
        ) : (
          // Re-key on the active project so every page reloads its data when it changes.
          <React.Suspense fallback={<p className="text-sm text-muted-foreground">Loading…</p>}>
            <Outlet key={activeProjectId ?? "all"} />
          </React.Suspense>
        )}
      </main>
    </div>
  );
}
