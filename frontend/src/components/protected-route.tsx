import { Navigate } from "react-router-dom";

import { useAuth } from "@/context/auth-context";
import { TwoFactorSetupPage } from "@/pages/two-factor-setup-page";

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) {
    return null;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  // REQUIRE_ADMIN_2FA: the server only lets this session set up a second factor.
  if (user.two_factor_setup_required) {
    return <TwoFactorSetupPage />;
  }

  return children;
}
