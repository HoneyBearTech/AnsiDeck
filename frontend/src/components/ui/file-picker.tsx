import { Upload } from "lucide-react";
import * as React from "react";

import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * A file input that looks like a button: the real (visually hidden, still focusable) input keeps the
 * label, keyboard use and the browser's file dialog; the label is what you see and click.
 */
export function FilePicker({
  id,
  label,
  accept,
  onFile,
}: {
  id: string;
  label: string;
  accept?: string;
  onFile: (file: File) => void;
}) {
  const [fileName, setFileName] = React.useState<string | null>(null);
  return (
    <div className="flex flex-wrap items-center gap-3">
      <input
        id={id}
        type="file"
        accept={accept}
        className="peer sr-only"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) {
            setFileName(file.name);
            onFile(file);
          }
          event.target.value = ""; // the same file can be picked again
        }}
      />
      <label
        htmlFor={id}
        className={cn(
          buttonVariants({ variant: "outline", size: "sm" }),
          "cursor-pointer peer-focus-visible:ring-2 peer-focus-visible:ring-ring peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-background",
        )}
      >
        <Upload aria-hidden="true" className="size-4" />
        {label}
      </label>
      <span className="text-xs text-muted-foreground">{fileName ?? "No file chosen"}</span>
    </div>
  );
}
