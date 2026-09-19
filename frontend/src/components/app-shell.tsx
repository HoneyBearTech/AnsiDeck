import { NavLink, Outlet } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { useAuth } from "@/context/auth-context";
import { cn } from "@/lib/utils";

function NavItem({ to, label, permission }: { to: string; label: string; permission?: string }) {
  const { can } = useAuth();
  if (permission && !can(permission)) return null;

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

export function AppShell() {
  const { user, logout } = useAuth();

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
            <NavItem to="/users" label="Users" permission="users:manage" />
            <NavItem to="/audit" label="Audit" permission="audit:read" />
          </nav>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-muted-foreground">
            {user?.username} · {user?.role}
          </span>
          <Button variant="outline" size="sm" onClick={() => logout()}>
            Log out
          </Button>
        </div>
      </header>
      <main className="mx-auto max-w-5xl p-8">
        <Outlet />
      </main>
    </div>
  );
}
