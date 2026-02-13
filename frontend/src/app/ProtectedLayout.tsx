import { Navigate, Outlet, useLocation } from "react-router-dom";

import Shell from "@/layout/Shell";
import Loading from "@/shared/components/Loading";
import { useAuth } from "@/features/auth/context";

export default function ProtectedLayout() {
  const { status } = useAuth();
  const loc = useLocation();

  if (status === "loading") {
    return (
      <div className="min-h-screen bg-background text-foreground flex items-center justify-center p-6">
        <div className="w-full max-w-md">
          <Loading label="Restoring session" />
        </div>
      </div>
    );
  }

  if (status !== "authed") {
    return <Navigate to="/login" replace state={{ from: loc }} />;
  }

  return (
    <Shell>
      <Outlet />
    </Shell>
  );
}
