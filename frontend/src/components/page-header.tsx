import { ChevronLeft } from "lucide-react";
import type * as React from "react";
import { Link } from "react-router-dom";

/**
 * The top of every page: an optional back link, the page's one <h1>, an optional description, and the
 * page's main actions on the right (stacked under the title on small screens).
 */
export function PageHeader({
  title,
  description,
  back,
  actions,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  back?: { to: string; label: string } | undefined;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3">
      {back && (
        <Link
          to={back.to}
          className="flex min-h-6 w-fit items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ChevronLeft aria-hidden="true" className="size-4" />
          {back.label}
        </Link>
      )}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
        <div className="flex min-w-0 flex-col gap-1">
          <h1 className="text-xl font-semibold wrap-anywhere">{title}</h1>
          {description && <div className="text-sm text-muted-foreground">{description}</div>}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  );
}
