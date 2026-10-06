import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/context/auth-context";

/** The item's project, shown only while viewing all projects (otherwise it's the active one). */
export function ProjectBadge({ projectId }: { projectId: number }) {
  const { user, activeProjectId } = useAuth();
  if (activeProjectId !== null) return null;
  const name = user?.projects.find((p) => p.id === projectId)?.name ?? `project #${projectId}`;
  return <Badge variant="outline">{name}</Badge>;
}
