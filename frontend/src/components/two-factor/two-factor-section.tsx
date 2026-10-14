import * as React from "react";

import { api, type AuthProviders, type User } from "@/lib/api";

import { PasskeysCard } from "./passkeys-card";
import { RecoveryCodesCard } from "./recovery-codes-card";
import { TotpCard } from "./totp-card";

/** Every second factor of the signed-in user: passkeys, an authenticator app, recovery codes. */
export function TwoFactorSection({ user }: { user: User }) {
  const [providers, setProviders] = React.useState<AuthProviders | null>(null);

  React.useEffect(() => {
    api
      .getAuthProviders()
      .then(setProviders)
      .catch(() => setProviders(null));
  }, []);

  return (
    <>
      <PasskeysCard user={user} providers={providers} />
      <TotpCard user={user} />
      {(user.two_factor_enabled ?? user.totp_enabled) && <RecoveryCodesCard user={user} />}
    </>
  );
}
