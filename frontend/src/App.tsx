import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/app-shell";
import { ProtectedRoute } from "@/components/protected-route";
import { RequirePermission } from "@/components/require-permission";
import { AuthProvider } from "@/context/auth-context";
import { AuditPage } from "@/pages/audit-page";
import { CredentialsPage } from "@/pages/credentials-page";
import { DashboardPage } from "@/pages/dashboard-page";
import { GalaxyPage } from "@/pages/galaxy-page";
import { InventoriesPage } from "@/pages/inventories-page";
import { InventoryDetailPage } from "@/pages/inventory-detail-page";
import { LoginPage } from "@/pages/login-page";
import { PlaybookDetailPage } from "@/pages/playbook-detail-page";
import { PlaybooksPage } from "@/pages/playbooks-page";
import { ProjectsPage } from "@/pages/projects-page";
import { RunDetailPage } from "@/pages/run-detail-page";
import { RunTriggerPage } from "@/pages/run-trigger-page";
import { RunsPage } from "@/pages/runs-page";
import { UsersPage } from "@/pages/users-page";
import { VaultPage } from "@/pages/vault-page";

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
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}

export default App;
