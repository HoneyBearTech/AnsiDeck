import type { BadgeProps } from "@/components/ui/badge";
import type { Run } from "@/lib/api";

// What the API puts in place of a value it won't show (secret-looking names; extra vars hidden from
// people who may not read them).
const MASKS = new Set(["[REDACTED]", "[HIDDEN]"]);

/** The items a run used that have since been deleted (it can't be started again as it was). */
export function deletedItems(run: Run): string[] {
  const missing: string[] = [];
  if (run.playbook_id === null) missing.push("playbook");
  if (run.inventory_id === null) missing.push("inventory");
  if (run.credential_id === null) missing.push("credential");
  if (run.vault_password_name !== null && run.vault_password_id === null) missing.push("vault password");
  return missing;
}

/** "its credential has been deleted" / "its playbook, inventory have been deleted". */
export function describeDeleted(missing: string[]): string {
  return `its ${missing.join(", ")} ${missing.length === 1 ? "has" : "have"} been deleted`;
}

/** Whether extra vars still hold a masked placeholder somewhere (not the real value). */
export function hasMaskedValue(value: unknown): boolean {
  if (typeof value === "string") return MASKS.has(value);
  if (Array.isArray(value)) return value.some(hasMaskedValue);
  if (value !== null && typeof value === "object") return Object.values(value).some(hasMaskedValue);
  return false;
}

export const STATUS_VARIANT: Record<Run["status"], BadgeProps["variant"]> = {
  success: "ok",
  failed: "failed",
  running: "changed",
  queued: "skipped",
  cancelled: "skipped",
  timed_out: "failed",
};

/** "4.2 s" or "3 min 12 s" between two timestamps, or null if either is missing. */
export function formatDuration(from: string | null, to: string | null): string | null {
  if (!from || !to) return null;
  const s = (new Date(to).getTime() - new Date(from).getTime()) / 1000;
  return s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)} min ${Math.floor(s % 60)} s`;
}
