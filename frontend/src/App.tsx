import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/app-shell";
import { ProtectedRoute } from "@/components/protected-route";
import { AuthProvider } from "@/context/auth-context";
import { CredentialsPage } from "@/pages/credentials-page";
import { DashboardPage } from "@/pages/dashboard-page";
import { InventoriesPage } from "@/pages/inventories-page";
import { InventoryDetailPage } from "@/pages/inventory-detail-page";
import { LoginPage } from "@/pages/login-page";
import { PlaybookDetailPage } from "@/pages/playbook-detail-page";
import { PlaybooksPage } from "@/pages/playbooks-page";

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
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}

export default App;
