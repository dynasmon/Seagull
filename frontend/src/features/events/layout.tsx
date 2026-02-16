import type { ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";

import { EventsHeaderContext } from "./header";

type HeaderMeta = {
  title: string;
  description?: string;
};

function metaForPath(pathname: string): HeaderMeta {
  if (pathname.startsWith("/events/ssh")) {
    return {
      title: "SSH Insights",
      description: "Authentication + sudo telemetry: top IPs/users, failures, and recent activity."
    };
  }
  if (pathname.startsWith("/events/network")) {
    return {
      title: "Protocol Intelligence",
      description:
        "Protocol-aware metadata derived from network signals: DNS queries, HTTP hosts/methods, and TLS/DTLS/QUIC fingerprints (JA3/JA4)."
    };
  }
  return {
    title: "Events",
    description: "Fleet telemetry stream: filter, pivot and inspect individual events."
  };
}

export default function EventsLayout() {
  const location = useLocation();

  const [toolbarRight, setToolbarRight] = useState<ReactNode | null>(null);

  // Avoid “sticky” toolbars when navigating between the events sub-views.
  useEffect(() => {
    setToolbarRight(null);
  }, [location.pathname]);

  const meta = useMemo(() => metaForPath(location.pathname), [location.pathname]);

  const tabs = useMemo(
    () => [
      { label: "Event Stream", to: "/events" },
      { label: "SSH Insights", to: "/events/ssh" },
      { label: "Protocol Intel", to: "/events/network" }
    ],
    []
  );

  const api = useMemo(() => ({ setToolbarRight }), []);

  return (
    <EventsHeaderContext.Provider value={api}>
      <div className="p-5 space-y-5 min-h-0">
        <PageHeader breadcrumb="Telemetry" title={meta.title} description={meta.description} tabs={tabs} toolbarRight={toolbarRight} />
        <Outlet />
      </div>
    </EventsHeaderContext.Provider>
  );
}
