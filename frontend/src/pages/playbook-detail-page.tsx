import * as React from "react";
import { useNavigate, useParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api, ApiError } from "@/lib/api";

export function PlaybookDetailPage() {
  const params = useParams<{ id: string }>();
  const navigate = useNavigate();
  const isNew = params.id === undefined;
  const playbookId = params.id ? Number(params.id) : null;

  const [name, setName] = React.useState("");
  const [content, setContent] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [loading, setLoading] = React.useState(!isNew);

  React.useEffect(() => {
    if (playbookId === null) return;
    api.getPlaybook(playbookId).then((playbook) => {
      setName(playbook.name);
      setContent(playbook.content);
      setLoading(false);
    });
  }, [playbookId]);

  async function handleFileUpload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setContent(text);
    if (!name) setName(file.name);
  }

  async function handleSave() {
    setError(null);
    setSaving(true);
    try {
      if (playbookId === null) {
        const created = await api.createPlaybook(name, content);
        navigate(`/playbooks/${created.id}`);
      } else {
        await api.updatePlaybook(playbookId, { name, content });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">{isNew ? "New Playbook" : "Edit Playbook"}</h1>

      <div className="flex flex-col gap-2">
        <Label htmlFor="playbook-name">Name</Label>
        <Input id="playbook-name" value={name} onChange={(e) => setName(e.target.value)} />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="playbook-file">Upload YAML file</Label>
        <input
          id="playbook-file"
          type="file"
          accept=".yml,.yaml"
          onChange={handleFileUpload}
          className="text-sm text-muted-foreground"
        />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="playbook-content">Content</Label>
        <Textarea
          id="playbook-content"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          className="min-h-96 font-mono"
          spellCheck={false}
        />
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <div>
        <Button onClick={handleSave} disabled={saving || !name || !content}>
          {saving ? "Saving…" : "Save"}
        </Button>
      </div>
    </div>
  );
}
