import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/app-shell";
import { ProtectedRoute } from "@/components/protected-route";
import { AuthProvider } from "@/context/auth-context";
import { CredentialsPage } from "@/pages/credentials-page";
import { DashboardPage } from "@/pages/dashboard-page";
import { GalaxyPage } from "@/pages/galaxy-page";
import { InventoriesPage } from "@/pages/inventories-page";
import { InventoryDetailPage } from "@/pages/inventory-detail-page";
import { LoginPage } from "@/pages/login-page";
import { PlaybookDetailPage } from "@/pages/playbook-detail-page";
import { PlaybooksPage } from "@/pages/playbooks-page";
import { RunDetailPage } from "@/pages/run-detail-page";
import { RunTriggerPage } from "@/pages/run-trigger-page";
import { RunsPage } from "@/pages/runs-page";
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
          <Route path="/playbooks/new" element={<PlaybookDetailPage />} />
          <Route path="/playbooks/:id" element={<PlaybookDetailPage />} />
          <Route path="/inventories" element={<InventoriesPage />} />
          <Route path="/inventories/:id" element={<InventoryDetailPage />} />
          <Route path="/credentials" element={<CredentialsPage />} />
          <Route path="/galaxy" element={<GalaxyPage />} />
          <Route path="/vault" element={<VaultPage />} />
          <Route path="/runs" element={<RunsPage />} />
          <Route path="/runs/new" element={<RunTriggerPage />} />
          <Route path="/runs/:id" element={<RunDetailPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}

export default App;
