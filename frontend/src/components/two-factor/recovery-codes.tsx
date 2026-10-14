import * as React from "react";

import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api";
import { passkeyProblem } from "@/lib/webauthn";

// An API error's message, the browser's passkey problem, or a generic one.
// oxlint-disable-next-line react/only-export-components -- shared by the two-factor cards
export function problemMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  return passkeyProblem(err) ?? "Something went wrong";
}

export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [copied, setCopied] = React.useState(false);
  const text = codes.join("\n") + "\n";

  async function handleCopy() {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function handleDownload() {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "ansideck-recovery-codes.txt";
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm">
        Save these recovery codes somewhere safe. Each one signs you in once if you lose your authenticator
        app and passkeys. They won't be shown again.
      </p>
      <ul className="grid max-w-sm grid-cols-2 gap-x-6 gap-y-1 rounded-md border border-border bg-muted p-4 font-mono text-sm">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" size="sm" onClick={handleCopy}>
          {copied ? "Copied" : "Copy"}
        </Button>
        <Button variant="outline" size="sm" onClick={handleDownload}>
          Download .txt
        </Button>
        <Button size="sm" onClick={onDone}>
          I've saved them
        </Button>
      </div>
    </div>
  );
}
