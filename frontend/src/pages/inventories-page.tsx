import * as React from "react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";
import { api, ApiError, type InventorySummary } from "@/lib/api";

export function InventoriesPage() {
  const { can } = useAuth();
  const canWrite = can("content:write");
  const [inventories, setInventories] = React.useState<InventorySummary[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  const refresh = React.useCallback(() => {
    api.listInventories().then((i) => {
      setInventories(i);
      setLoading(false);
    });
  }, []);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleCreate() {
    setError(null);
    try {
      await api.createInventory(name, description || undefined);
      setName("");
      setDescription("");
      setDialogOpen(false);
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    }
  }

  async function handleDelete(id: number) {
    await api.deleteInventory(id);
    refresh();
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Inventories</h1>
        {canWrite && (
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button>New Inventory</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>New Inventory</DialogTitle>
              </DialogHeader>
              <div className="flex flex-col gap-4">
                <div className="flex flex-col gap-2">
                  <Label htmlFor="inventory-name">Name</Label>
                  <Input id="inventory-name" value={name} onChange={(e) => setName(e.target.value)} />
                </div>
                <div className="flex flex-col gap-2">
                  <Label htmlFor="inventory-description">Description</Label>
                  <Input
                    id="inventory-description"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>
                {error && <p className="text-sm text-destructive">{error}</p>}
              </div>
              <DialogFooter>
                <Button onClick={handleCreate} disabled={!name}>
                  Create
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </div>

      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {!loading && inventories.length === 0 && (
        <p className="text-sm text-muted-foreground">No inventories yet.</p>
      )}

      <div className="flex flex-col gap-2">
        {inventories.map((inventory) => (
          <Card key={inventory.id}>
            <CardContent className="flex items-center justify-between p-4">
              <Link to={`/inventories/${inventory.id}`} className="flex flex-col gap-1">
                <span className="font-medium">{inventory.name}</span>
                {inventory.description && (
                  <span className="text-xs text-muted-foreground">{inventory.description}</span>
                )}
              </Link>
              {canWrite && (
                <Button variant="outline" size="sm" onClick={() => handleDelete(inventory.id)}>
                  Delete
                </Button>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
