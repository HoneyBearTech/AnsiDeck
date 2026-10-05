import * as React from "react";

import { useAuth } from "@/context/auth-context";
import { api, type SecretStoreInfo } from "@/lib/api";

/** The secret store's settings for the project a new secret goes to: the active one or, for
 * an admin working across all projects, the only one (null while loading or without one). */
export function useSecretStoreInfo(): SecretStoreInfo | null {
  const { user, activeProject } = useAuth();
  const projects = user?.projects ?? [];
  const projectId = activeProject?.id ?? (projects.length === 1 ? (projects[0]?.id ?? null) : null);
  const [loaded, setLoaded] = React.useState<{ projectId: number; info: SecretStoreInfo | null } | null>(
    null,
  );
  React.useEffect(() => {
    if (projectId === null) return;
    let cancelled = false;
    api
      .secretStoreInfo(projectId)
      .then((info) => !cancelled && setLoaded({ projectId, info }))
      .catch(() => !cancelled && setLoaded({ projectId, info: null }));
    return () => {
      cancelled = true;
    };
  }, [projectId]);
  // Never another project's base path while the new one loads.
  return loaded && loaded.projectId === projectId ? loaded.info : null;
}
