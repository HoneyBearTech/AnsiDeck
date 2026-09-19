import { useAuth } from "@/context/auth-context";

export function RequirePermission({
  permission,
  children,
}: {
  permission: string;
  children: React.ReactNode;
}) {
  const { can } = useAuth();

  if (!can(permission)) {
    return (
      <div className="flex flex-col gap-2">
        <h1 className="text-xl font-semibold">Not permitted</h1>
        <p className="text-sm text-muted-foreground">
          Your role doesn't allow you to view this page. Ask an admin if you need access.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
