import { ChevronDown, ChevronRight } from "lucide-react";
import * as React from "react";

import { OriginBadge } from "@/components/origin-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { InventoryGraph } from "@/lib/api";
import { GROUP_BOTH_TITLE, type GroupIndex } from "@/lib/group-graph";
import { cn } from "@/lib/utils";

type Group = InventoryGraph["groups"][number];

// Rows shown per level before "Show more", and the most search matches listed.
const STEP = 100;
const MAX_MATCHES = 200;
// "Expand all" only while everything fits in this many rows (a group with several parents
// appears under each of them, so a full expansion can be much bigger than the group count).
const MAX_EXPANDED_ROWS = 300;
const SEP = "\u001f";
const ROOT = "";

type Row =
  | { kind: "group"; key: string; name: string; level: number; pos: number; size: number; parentKey: string | null; parentName: string | null; expandable: boolean; expanded: boolean }
  | { kind: "more"; key: string; level: number; pos: number; size: number; parentKey: string | null; remaining: number };

function buildRows(index: GroupIndex, expanded: Set<string>, shown: Map<string, number>, limit = Infinity): Row[] {
  const rows: Row[] = [];
  const visit = (names: string[], path: string[], level: number, parentKey: string | null) => {
    const count = shown.get(parentKey ?? ROOT) ?? STEP;
    for (const [i, name] of names.slice(0, count).entries()) {
      if (rows.length >= limit) return;
      const key = [...path, name].join(SEP);
      const kids = index.childrenOf(name);
      const open = kids.length > 0 && expanded.has(key) && !path.includes(name);
      rows.push({ kind: "group", key, name, level, pos: i + 1, size: names.length, parentKey, parentName: path.at(-1) ?? null, expandable: kids.length > 0, expanded: open });
      if (open) visit(kids, [...path, name], level + 1, key);
    }
    if (names.length > count && rows.length < limit) {
      rows.push({ kind: "more", key: `${parentKey ?? ROOT}${SEP}more`, level, pos: count + 1, size: names.length, parentKey, remaining: names.length - count });
    }
  };
  visit(index.roots, [], 1, null);
  return rows;
}

/** Every expandable path, for "Expand all" (only called when the result stays small). */
function allPaths(index: GroupIndex): Set<string> {
  const keys = new Set<string>();
  const visit = (names: string[], path: string[]) => {
    for (const name of names) {
      const kids = index.childrenOf(name);
      if (kids.length === 0 || path.includes(name)) continue;
      const next = [...path, name];
      keys.add(next.join(SEP));
      visit(kids, next);
    }
  };
  visit(index.roots, []);
  return keys;
}

/**
 * The inventory's groups as a tree (WAI-ARIA tree pattern): top-level groups first, children on
 * demand. A group with several parents appears under each of them. Search lists the matching
 * groups instead.
 */
export function GroupTree({
  graph,
  index,
  selected,
  onSelect,
}: {
  graph: InventoryGraph;
  index: GroupIndex;
  selected: string | null;
  onSelect: (name: string) => void;
}) {
  const [expanded, setExpanded] = React.useState<Set<string>>(() => new Set());
  const [shown, setShown] = React.useState<Map<string, number>>(() => new Map());
  const [query, setQuery] = React.useState("");
  const [focusKey, setFocusKey] = React.useState<string | null>(null);
  const rowRefs = React.useRef(new Map<string, HTMLLIElement>());
  const moveFocus = React.useRef(false);

  const rows = React.useMemo(() => buildRows(index, expanded, shown), [index, expanded, shown]);
  const canExpandAll = React.useMemo(() => {
    const full = buildRows(index, allPaths(index), new Map(), MAX_EXPANDED_ROWS + 1);
    return full.length <= MAX_EXPANDED_ROWS && full.some((r) => r.kind === "group" && r.expandable);
  }, [index]);

  // The one row in the Tab order: the focused one, else the first selected one, else the first.
  const tabKey =
    (focusKey && rows.some((r) => r.key === focusKey) && focusKey) ||
    rows.find((r) => r.kind === "group" && r.name === selected)?.key ||
    rows[0]?.key;

  React.useEffect(() => {
    if (!moveFocus.current || !tabKey) return;
    moveFocus.current = false;
    rowRefs.current.get(tabKey)?.focus();
  }, [tabKey]);

  function focus(key: string | undefined) {
    if (!key) return;
    moveFocus.current = true;
    setFocusKey(key);
  }

  function toggle(key: string, open: boolean) {
    setExpanded((current) => {
      const next = new Set(current);
      if (open) next.add(key);
      else next.delete(key);
      return next;
    });
  }

  function showMore(parentKey: string | null) {
    const at = parentKey ?? ROOT;
    setShown((current) => new Map(current).set(at, (current.get(at) ?? STEP) + STEP));
  }

  function activate(row: Row) {
    if (row.kind === "more") {
      showMore(row.parentKey);
      return;
    }
    onSelect(row.name);
  }

  function onKeyDown(event: React.KeyboardEvent, row: Row, i: number) {
    const keys: Record<string, () => void> = {
      ArrowDown: () => focus(rows[i + 1]?.key),
      ArrowUp: () => focus(rows[i - 1]?.key),
      Home: () => focus(rows[0]?.key),
      End: () => focus(rows.at(-1)?.key),
      ArrowRight: () => {
        if (row.kind !== "group" || !row.expandable) return;
        if (!row.expanded) toggle(row.key, true);
        else focus(rows[i + 1]?.key);
      },
      ArrowLeft: () => {
        if (row.kind === "group" && row.expanded) toggle(row.key, false);
        else if (row.parentKey) focus(row.parentKey);
      },
      Enter: () => activate(row),
      " ": () => activate(row),
    };
    const action = keys[event.key];
    if (!action) return;
    event.preventDefault();
    action();
  }

  const needle = query.trim().toLowerCase();
  const matches = needle ? graph.groups.filter((g) => g.name.toLowerCase().includes(needle)) : [];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          aria-label="Search groups"
          placeholder="Search groups"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="h-8 min-w-0 flex-1 basis-40"
        />
        {!needle && (
          <span className="flex gap-2">
            <Button variant="outline" size="sm" disabled={!canExpandAll} onClick={() => setExpanded(allPaths(index))}>
              Expand all
            </Button>
            <Button variant="outline" size="sm" disabled={expanded.size === 0} onClick={() => setExpanded(new Set())}>
              Collapse all
            </Button>
          </span>
        )}
      </div>

      {graph.groups.length === 0 && <p className="text-sm text-muted-foreground">This inventory has no groups.</p>}

      {needle ? (
        <SearchResults matches={matches} index={index} selected={selected} onSelect={onSelect} />
      ) : (
        rows.length > 0 && (
          <ul role="tree" aria-label="Groups" className="flex flex-col gap-0.5">
            {rows.map((row, i) => {
              const isSelected = row.kind === "group" && row.name === selected;
              const otherParents =
                row.kind === "group" ? (index.parents.get(row.name) ?? []).filter((p) => p !== row.parentName) : [];
              return (
                <li
                  key={row.key}
                  ref={(el) => {
                    if (el) rowRefs.current.set(row.key, el);
                    else rowRefs.current.delete(row.key);
                  }}
                  role="treeitem"
                  aria-level={row.level}
                  aria-posinset={row.pos}
                  aria-setsize={row.size}
                  aria-expanded={row.kind === "group" && row.expandable ? row.expanded : undefined}
                  aria-selected={row.kind === "group" ? isSelected : undefined}
                  tabIndex={row.key === tabKey ? 0 : -1}
                  onKeyDown={(e) => onKeyDown(e, row, i)}
                  onFocus={() => setFocusKey(row.key)}
                  onClick={() => activate(row)}
                  style={{ paddingLeft: `${(row.level - 1) * 1.25}rem` }}
                  className={cn(
                    "flex min-h-9 cursor-pointer items-center gap-1 rounded-md pr-2 text-sm outline-none hover:bg-secondary/50 focus-visible:ring-2 focus-visible:ring-ring pointer-coarse:min-h-10",
                    isSelected && "bg-secondary text-foreground",
                  )}
                >
                  {row.kind === "more" ? (
                    <span className="pl-7 text-primary">Show {Math.min(STEP, row.remaining)} more of {row.remaining}</span>
                  ) : (
                    <>
                      <span
                        aria-hidden="true"
                        className="flex size-7 shrink-0 items-center justify-center text-muted-foreground"
                        onClick={(e) => {
                          if (!row.expandable) return;
                          e.stopPropagation();
                          toggle(row.key, !row.expanded);
                        }}
                      >
                        {row.expandable && (row.expanded ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />)}
                      </span>
                      <span className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-0.5 py-1">
                        <span className="font-mono wrap-anywhere">{row.name}</span>
                        <span className="text-xs text-muted-foreground">
                          {index.byName.get(row.name)?.hosts ?? 0} {index.byName.get(row.name)?.hosts === 1 ? "host" : "hosts"}
                        </span>
                        {otherParents.length > 0 && (
                          <span className="text-xs text-muted-foreground wrap-anywhere">
                            also under {otherParents.slice(0, 3).join(", ")}
                            {otherParents.length > 3 && ` and ${otherParents.length - 3} more`}
                          </span>
                        )}
                      </span>
                      <OriginBadge origin={index.byName.get(row.name)?.origin ?? "static"} bothTitle={GROUP_BOTH_TITLE} />
                    </>
                  )}
                </li>
              );
            })}
          </ul>
        )
      )}
    </div>
  );
}

function SearchResults({
  matches,
  index,
  selected,
  onSelect,
}: {
  matches: Group[];
  index: GroupIndex;
  selected: string | null;
  onSelect: (name: string) => void;
}) {
  if (matches.length === 0) return <p className="text-sm text-muted-foreground">No groups match.</p>;
  return (
    <div className="flex flex-col gap-2">
      <ul aria-label="Matching groups" className="flex flex-col gap-0.5">
        {matches.slice(0, MAX_MATCHES).map((group) => {
          const parents = index.parents.get(group.name) ?? [];
          return (
            <li key={group.name}>
              <button
                type="button"
                aria-current={group.name === selected ? "true" : undefined}
                onClick={() => onSelect(group.name)}
                className={cn(
                  "flex min-h-9 w-full flex-wrap items-center gap-x-2 gap-y-0.5 rounded-md px-2 py-1 text-left text-sm hover:bg-secondary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring pointer-coarse:min-h-10",
                  group.name === selected && "bg-secondary",
                )}
              >
                <span className="font-mono wrap-anywhere">{group.name}</span>
                <span className="text-xs text-muted-foreground">
                  {group.hosts} {group.hosts === 1 ? "host" : "hosts"}
                </span>
                <span className="text-xs text-muted-foreground wrap-anywhere">
                  {parents.length === 0 ? "top level" : `under ${parents.slice(0, 3).join(", ")}${parents.length > 3 ? ` and ${parents.length - 3} more` : ""}`}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
      {matches.length > MAX_MATCHES && (
        <p className="text-xs text-muted-foreground">
          Showing {MAX_MATCHES} of {matches.length} matches: narrow your search.
        </p>
      )}
    </div>
  );
}
