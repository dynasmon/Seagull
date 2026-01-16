import { useState } from "react";
import Sidebar from "@/layout/Sidebar";
import TopBar from "@/layout/TopBar";

export default function Shell({ children }: { children: React.ReactNode }) {
  const [navCollapsed, setNavCollapsed] = useState(false);

  return (
    <div className="min-h-screen bg-bg text-fg">
      <div className="flex min-h-screen">
        <Sidebar collapsed={navCollapsed} />
        <div className="flex w-full flex-col">
          <TopBar onToggleNav={() => setNavCollapsed((v) => !v)} />
          <main className="flex-1 p-6">{children}</main>
        </div>
      </div>
    </div>
  );
}
