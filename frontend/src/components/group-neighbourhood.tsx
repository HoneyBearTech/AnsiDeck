import type * as React from "react";

import type { GroupIndex } from "@/lib/group-graph";

// Boxes per column before "and N more", and the box pitch the connectors are drawn for
// (h-10 boxes + gap-2), so nothing has to be measured.
const MAX_BOXES = 8;
const BOX = 40;
const GAP = 8;
const PITCH = BOX + GAP;
const CONNECTOR = 40;

function columnHeight(count: number) {
  return Math.max(count, 1) * PITCH - GAP;
}

/** Vertical centres of `count` boxes stacked in a column centred in `height`. */
function centres(count: number, height: number) {
  const top = (height - columnHeight(count)) / 2;
  return Array.from({ length: count }, (_, i) => top + i * PITCH + BOX / 2);
}

/** Slots in a column: its boxes, plus one for the "and N more" line. */
function slots(count: number) {
  return Math.min(count, MAX_BOXES) + (count > MAX_BOXES ? 1 : 0);
}

function Connectors({ count, height, side }: { count: number; height: number; side: "in" | "out" }) {
  // "in": the parent boxes on the left join the middle; "out": the middle fans out to the children.
  const many = centres(slots(count), height).slice(0, Math.min(count, MAX_BOXES));
  const middle = height / 2;
  return (
    <svg aria-hidden="true" width={CONNECTOR} height={height} className="hidden shrink-0 text-border sm:block">
      {many.map((y) => (
        <path
          key={y}
          d={side === "in" ? `M0 ${y} C${CONNECTOR / 2} ${y} ${CONNECTOR / 2} ${middle} ${CONNECTOR} ${middle}` : `M0 ${middle} C${CONNECTOR / 2} ${middle} ${CONNECTOR / 2} ${y} ${CONNECTOR} ${y}`}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
        />
      ))}
    </svg>
  );
}

function Column({
  label,
  names,
  index,
  height,
  onSelect,
  empty,
}: {
  label: string;
  names: string[];
  index: GroupIndex;
  height: number;
  onSelect: (name: string) => void;
  empty: string;
}) {
  const visible = names.slice(0, MAX_BOXES);
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-1">
      <span className="text-xs text-muted-foreground sm:sr-only">{label}</span>
      <ul aria-label={label} className="flex flex-col justify-center gap-2 sm:min-h-[var(--column-height)]" style={{ "--column-height": `${height}px` } as React.CSSProperties}>
        {visible.map((name) => (
          <li key={name}>
            <button
              type="button"
              onClick={() => onSelect(name)}
              className="flex h-10 w-full items-center justify-between gap-2 rounded-md border border-border bg-card px-3 text-left text-sm hover:border-primary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <span className="min-w-0 truncate font-mono" title={name}>
                {name}
              </span>
              <span className="shrink-0 text-xs text-muted-foreground">{index.byName.get(name)?.hosts ?? 0}</span>
            </button>
          </li>
        ))}
        {names.length === 0 && <li className="text-xs text-muted-foreground">{empty}</li>}
        {names.length > MAX_BOXES && (
          <li className="flex h-10 items-center text-xs text-muted-foreground">
            and {names.length - MAX_BOXES} more (see the tree)
          </li>
        )}
      </ul>
    </div>
  );
}

/**
 * Where one group sits: its parent groups, the group, and its child groups, joined by lines on
 * wider screens and stacked on phones. Every other box selects that group.
 */
export function GroupNeighbourhood({
  name,
  index,
  onSelect,
}: {
  name: string;
  index: GroupIndex;
  onSelect: (name: string) => void;
}) {
  const parents = index.parents.get(name) ?? [];
  const children = index.childrenOf(name);
  const height = columnHeight(Math.max(slots(parents.length), slots(children.length), 1));
  const group = index.byName.get(name);

  return (
    <figure aria-label={`Where ${name} sits`} className="flex flex-col gap-3 sm:flex-row sm:items-start">
      <Column label="Parent groups" names={parents} index={index} height={height} onSelect={onSelect} empty="Top level: no parent group." />
      {parents.length > 0 ? <Connectors count={parents.length} height={height} side="in" /> : <span className="hidden w-10 shrink-0 sm:block" />}
      <div className="flex min-w-0 flex-1 flex-col gap-1 sm:justify-center sm:self-stretch">
        <span className="text-xs text-muted-foreground sm:sr-only">Selected group</span>
        <div className="flex h-10 items-center justify-between gap-2 rounded-md border-2 border-primary bg-primary/10 px-3 text-sm font-medium">
          <span className="min-w-0 truncate font-mono" title={name}>
            {name}
          </span>
          <span className="shrink-0 text-xs text-muted-foreground">{group?.hosts ?? 0}</span>
        </div>
      </div>
      {children.length > 0 ? <Connectors count={children.length} height={height} side="out" /> : <span className="hidden w-10 shrink-0 sm:block" />}
      <Column label="Child groups" names={children} index={index} height={height} onSelect={onSelect} empty="No child groups." />
    </figure>
  );
}
