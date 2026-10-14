import { TwoFactorSection } from "@/components/two-factor/two-factor-section";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/context/auth-context";

/** REQUIRE_ADMIN_2FA: an admin who signed in with the password alone sets up a second factor before
 * anything else (the server refuses everything else until then). */
export function TwoFactorSetupPage() {
  const { user, logout } = useAuth();
  if (!user) return null;

  return (
    <main className="min-h-screen bg-background px-4 py-10">
      <div className="mx-auto flex w-full max-w-2xl flex-col gap-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex flex-col gap-2">
            <span className="font-mono text-xl font-semibold text-primary">AnsiDeck</span>
            <h1 className="text-2xl font-semibold">Set up two-factor login</h1>
            <p className="text-sm text-muted-foreground">
              This server requires admins to use two-factor login. Add a passkey or an authenticator app to
              continue as {user.username}.
            </p>
          </div>
          <Button variant="outline" onClick={() => void logout()}>
            Sign out
          </Button>
        </div>
        <TwoFactorSection user={user} />
      </div>
    </main>
  );
}
