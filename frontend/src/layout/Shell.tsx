import { Suspense, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useLocation } from "react-router-dom";

import Sidebar from "@/layout/Sidebar";
import TopBar from "@/layout/TopBar";
import Loading from "@/shared/components/Loading";

const NAV_COMPACT_KEY = "nw_shell_nav_compact_v1";

function MainFallback() {
  return (
    <div className="space-y-3">
      <Loading label="Loading view..." />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div className="h-24 rounded-lg border border-border/60 bg-card/70" />
        <div className="h-24 rounded-lg border border-border/60 bg-card/70" />
      </div>
      <div className="h-64 rounded-lg border border-border/60 bg-card/70" />
    </div>
  );
}

function readInitialCompact(): boolean {
  try {
    return localStorage.getItem(NAV_COMPACT_KEY) === "1";
  } catch {
    return false;
  }
}

export default function Shell({ children }: { children: ReactNode }) {
  const location = useLocation();
  const [navCompact, setNavCompact] = useState<boolean>(() => readInitialCompact());
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem(NAV_COMPACT_KEY, navCompact ? "1" : "0");
    } catch {
      // no-op
    }
  }, [navCompact]);

  useEffect(() => {
    setMobileNavOpen(false);
  }, [location.pathname]);

  const shellClassName = useMemo(
    () => "h-screen overflow-hidden bg-background text-foreground",
    []
  );

  return (
    <div className={shellClassName}>
      <a
        href="#main-content"
        className="sr-only z-50 rounded-sm bg-primary px-3 py-2 text-sm text-primary-foreground focus:not-sr-only focus:fixed focus:left-3 focus:top-3"
      >
        Skip to main content
      </a>

      <div className="flex h-full min-h-0">
        <Sidebar
          compact={navCompact}
          mobileOpen={mobileNavOpen}
          onCloseMobile={() => setMobileNavOpen(false)}
        />

        <div className="flex min-w-0 min-h-0 flex-1 flex-col">
          <TopBar
            compact={navCompact}
            navigationOpen={mobileNavOpen}
            onToggleCompact={() => setNavCompact((prev) => !prev)}
            onToggleNavigation={() => setMobileNavOpen((prev) => !prev)}
          />

          <main id="main-content" role="main" className="flex-1 min-h-0 overflow-x-hidden overflow-y-auto [scrollbar-gutter:stable]">
            <div className="mx-auto w-full max-w-[1800px] px-4 py-4 sm:px-6 lg:px-8">
              <Suspense fallback={<MainFallback />}>
                <div key={location.pathname} className="page-transition-enter">
                  {children}
                </div>
              </Suspense>
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}
