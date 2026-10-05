import * as React from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/app-shell";
import { ProtectedRoute } from "@/components/protected-route";
import { RequirePermission } from "@/components/require-permission";
import { AuthProvider } from "@/context/auth-context";
import { DashboardPage } from "@/pages/dashboard-page";
import { LoginPage } from "@/pages/login-page";

// Pages other than sign-in and the dashboard load on first visit, keeping the initial bundle small.
const AccountPage = React.lazy(() => import("@/pages/account-page").then((m) => ({ default: m.AccountPage })));
const AuditPage = React.lazy(() => import("@/pages/audit-page").then((m) => ({ default: m.AuditPage })));
const CredentialsPage = React.lazy(() => import("@/pages/credentials-page").then((m) => ({ default: m.CredentialsPage })));
const GalaxyPage = React.lazy(() => import("@/pages/galaxy-page").then((m) => ({ default: m.GalaxyPage })));
const InventoriesPage = React.lazy(() => import("@/pages/inventories-page").then((m) => ({ default: m.InventoriesPage })));
const InventoryDetailPage = React.lazy(() => import("@/pages/inventory-detail-page").then((m) => ({ default: m.InventoryDetailPage })));
const NotificationsPage = React.lazy(() => import("@/pages/notifications-page").then((m) => ({ default: m.NotificationsPage })));
const PlaybookDetailPage = React.lazy(() => import("@/pages/playbook-detail-page").then((m) => ({ default: m.PlaybookDetailPage })));
const PlaybooksPage = React.lazy(() => import("@/pages/playbooks-page").then((m) => ({ default: m.PlaybooksPage })));
const ProjectsPage = React.lazy(() => import("@/pages/projects-page").then((m) => ({ default: m.ProjectsPage })));
const RunDetailPage = React.lazy(() => import("@/pages/run-detail-page").then((m) => ({ default: m.RunDetailPage })));
const RunTriggerPage = React.lazy(() => import("@/pages/run-trigger-page").then((m) => ({ default: m.RunTriggerPage })));
const RunsPage = React.lazy(() => import("@/pages/runs-page").then((m) => ({ default: m.RunsPage })));
const TemplatesPage = React.lazy(() => import("@/pages/templates-page").then((m) => ({ default: m.TemplatesPage })));
const UsersPage = React.lazy(() => import("@/pages/users-page").then((m) => ({ default: m.UsersPage })));
const VaultPage = React.lazy(() => import("@/pages/vault-page").then((m) => ({ default: m.VaultPage })));
const WorkersPage = React.lazy(() => import("@/pages/workers-page").then((m) => ({ default: m.WorkersPage })));

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          element={
            <ProtectedRoute>
              <AppShell />
            </ProtectedRoute>
          }
        >
          <Route path="/" element={<DashboardPage />} />
          <Route path="/account" element={<AccountPage />} />
          <Route path="/playbooks" element={<PlaybooksPage />} />
          <Route
            path="/playbooks/new"
            element={
              <RequirePermission permission="content:write">
                <PlaybookDetailPage />
              </RequirePermission>
            }
          />
          <Route path="/playbooks/:id" element={<PlaybookDetailPage />} />
          <Route path="/inventories" element={<InventoriesPage />} />
          <Route path="/inventories/:id" element={<InventoryDetailPage />} />
          <Route
            path="/credentials"
            element={
              <RequirePermission permission="secrets:list">
                <CredentialsPage />
              </RequirePermission>
            }
          />
          <Route path="/galaxy" element={<GalaxyPage />} />
          <Route
            path="/vault"
            element={
              <RequirePermission permission="secrets:list">
                <VaultPage />
              </RequirePermission>
            }
          />
          <Route
            path="/users"
            element={
              <RequirePermission permission="users:manage">
                <UsersPage />
              </RequirePermission>
            }
          />
          <Route
            path="/audit"
            element={
              <RequirePermission permission="audit:read">
                <AuditPage />
              </RequirePermission>
            }
          />
          <Route
            path="/workers"
            element={
              <RequirePermission permission="workers:read">
                <WorkersPage />
              </RequirePermission>
            }
          />
          <Route path="/notifications" element={<NotificationsPage />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/runs" element={<RunsPage />} />
          <Route
            path="/runs/new"
            element={
              <RequirePermission permission="runs:trigger">
                <RunTriggerPage />
              </RequirePermission>
            }
          />
          <Route path="/runs/:id" element={<RunDetailPage />} />
          <Route path="/templates" element={<TemplatesPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}

export default App;
