import { Badge } from "@/components/ui/badge";
import type { HostOrigin } from "@/lib/api";

/** Where a host or group comes from: the inventory itself, a dynamic source, or both. */
export function OriginBadge({
  origin,
  bothTitle = "From a source, with some vars set by the inventory itself",
}: {
  origin: HostOrigin;
  bothTitle?: string;
}) {
  if (origin === "static") return <Badge variant="outline">inventory</Badge>;
  if (origin === "source") return <Badge variant="skipped">source</Badge>;
  return (
    <Badge variant="skipped" title={bothTitle}>
      source + inventory
    </Badge>
  );
}
