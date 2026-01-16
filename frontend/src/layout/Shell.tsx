import { useState } from "react";
import type { ReactNode } from "react";
import Sidebar from "@/layout/Sidebar";
import TopBar from "@/layout/TopBar";

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
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
