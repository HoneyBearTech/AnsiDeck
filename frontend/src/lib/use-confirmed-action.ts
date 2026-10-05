import * as React from "react";

import { ApiError } from "@/lib/api";

/**
 * Runs a destructive action only after the person confirms it, then `onDone`; keeps the API's
 * reason when it refuses (e.g. something still uses the item) to show on the page.
 */
export function useConfirmedAction(onDone: () => void) {
  const [error, setError] = React.useState<string | null>(null);
  const run = React.useCallback(
    async (question: string, action: () => Promise<unknown>) => {
      if (!window.confirm(question)) return;
      setError(null);
      try {
        await action();
        onDone();
      } catch (err) {
        setError(err instanceof ApiError ? err.message : "Something went wrong");
      }
    },
    [onDone],
  );
  return { error, run };
}
