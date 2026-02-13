import { Suspense, useState } from "react";
import type { ReactNode } from "react";
import Sidebar from "@/layout/Sidebar";
import TopBar from "@/layout/TopBar";
import Loading from "@/shared/components/Loading";

function MainFallback() {
  return (
    <div className="space-y-3">
      <Loading label="Loading view…" />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div className="h-24 rounded-xl border border-border/60 bg-card/10" />
        <div className="h-24 rounded-xl border border-border/60 bg-card/10" />
      </div>
      <div className="h-64 rounded-xl border border-border/60 bg-card/10" />
    </div>
  );
}

export default function Shell({ children }: { children: ReactNode }) {
  const [navCollapsed, setNavCollapsed] = useState(false);

  return (
    <div className="h-screen overflow-hidden bg-background text-foreground">
      <div className="flex h-screen">
        <Sidebar collapsed={navCollapsed} />

        <div className="flex min-w-0 flex-1 flex-col">
          <div className="shrink-0">
            <TopBar onToggleNav={() => setNavCollapsed((v) => !v)} />
          </div>

          <main className="flex-1 min-h-0 overflow-y-auto p-6">
            <Suspense fallback={<MainFallback />}>{children}</Suspense>
          </main>
        </div>
      </div>
    </div>
  );
}
