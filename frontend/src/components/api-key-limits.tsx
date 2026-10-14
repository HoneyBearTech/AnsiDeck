import * as React from "react";

import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api, type ApiKey, type ApiKeyLimits, type InventorySummary, type PlaybookSummary } from "@/lib/api";

/** A key's limits in a line, or nothing when it has none. */
export function ApiKeyLimitsSummary({ apiKey }: { apiKey: ApiKey }) {
  const parts: string[] = [];
  if (apiKey.allowed_networks) parts.push(`from ${apiKey.allowed_networks.join(", ")}`);
  if (apiKey.allowed_playbooks) {
    parts.push(`playbooks: ${apiKey.allowed_playbooks.map((p) => p.name).join(", ") || "none left"}`);
  }
  if (apiKey.allowed_inventories) {
    parts.push(`inventories: ${apiKey.allowed_inventories.map((i) => i.name).join(", ") || "none left"}`);
  }
  if (parts.length === 0) return null;
  return <span className="text-xs text-muted-foreground wrap-anywhere">Only {parts.join(" · ")}</span>;
}

function Picker({
  legend,
  items,
  chosen,
  onChange,
}: {
  legend: string;
  items: { id: number; name: string }[];
  chosen: number[] | null;
  onChange: (ids: number[] | null) => void;
}) {
  const limited = chosen !== null;
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="mb-1 text-sm font-medium">{legend}</legend>
      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={limited} onCheckedChange={(on) => onChange(on === true ? [] : null)} />
        Only some
      </label>
      {limited && (
        <div className="flex max-h-40 flex-col gap-1 overflow-y-auto pl-6">
          {items.length === 0 && <p className="text-xs text-muted-foreground">None in this project.</p>}
          {items.map((item) => (
            <label key={item.id} className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={chosen.includes(item.id)}
                onCheckedChange={(on) =>
                  onChange(on === true ? [...chosen, item.id] : chosen.filter((id) => id !== item.id))
                }
              />
              <span className="wrap-anywhere">{item.name}</span>
            </label>
          ))}
        </div>
      )}
    </fieldset>
  );
}

/**
 * Limits for an API key: the addresses it may be used from, and the playbooks and inventories it
 * may start runs of. `null` in a field means any.
 */
export function ApiKeyLimitsEditor({
  projectId,
  idPrefix,
  value,
  onChange,
}: {
  projectId: number;
  idPrefix: string;
  value: ApiKeyLimits;
  onChange: (limits: ApiKeyLimits) => void;
}) {
  const [playbooks, setPlaybooks] = React.useState<PlaybookSummary[]>([]);
  const [inventories, setInventories] = React.useState<InventorySummary[]>([]);
  const [networks, setNetworks] = React.useState((value.allowed_networks ?? []).join("\n"));

  React.useEffect(() => {
    api.listPlaybooks().then((list) => setPlaybooks(list.filter((p) => p.project_id === projectId)));
    api.listInventories().then((list) => setInventories(list.filter((i) => i.project_id === projectId)));
  }, [projectId]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <Label htmlFor={`${idPrefix}-networks`}>Allowed addresses (optional, one per line)</Label>
        <Textarea
          id={`${idPrefix}-networks`}
          className="min-h-16 font-mono text-xs"
          placeholder="203.0.113.0/24"
          value={networks}
          onChange={(event) => {
            setNetworks(event.target.value);
            const list = event.target.value
              .split(/[\s,]+/)
              .map((n) => n.trim())
              .filter(Boolean);
            onChange({ ...value, allowed_networks: list.length > 0 ? list : null });
          }}
        />
        <p className="text-xs text-muted-foreground">
          Addresses or CIDRs (IPv4 or IPv6) the key may be used from, as AnsiDeck sees them behind your proxy.
          Empty: from anywhere.
        </p>
      </div>
      <Picker
        legend="Playbooks it may run"
        items={playbooks.filter((p) => p.missing_at === null)}
        chosen={value.allowed_playbook_ids}
        onChange={(ids) => onChange({ ...value, allowed_playbook_ids: ids })}
      />
      <Picker
        legend="Inventories it may run against"
        items={inventories}
        chosen={value.allowed_inventory_ids}
        onChange={(ids) => onChange({ ...value, allowed_inventory_ids: ids })}
      />
    </div>
  );
}
