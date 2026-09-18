import { type VariantProps, cva } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors duration-150 ease-out",
  {
    variants: {
      variant: {
        default: "border-transparent bg-secondary text-secondary-foreground",
        ok: "border-transparent bg-status-ok/15 text-status-ok",
        changed: "border-transparent bg-status-changed/15 text-status-changed",
        failed: "border-transparent bg-status-failed/15 text-status-failed",
        skipped: "border-transparent bg-status-skipped/15 text-status-skipped",
        outline: "border-border text-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant, className }))} {...props} />;
}

export { Badge, badgeVariants };
