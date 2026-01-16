import PageHeader from "@/shared/components/PageHeader";

export default function EventsPage() {
  return (
    <div>
      <PageHeader
        title="Security events"
        breadcrumb={["Modules", "Security events"]}
        tabs={[
          { label: "Dashboard", to: "/overview" },
          { label: "Events", to: "/events" },
          { label: "Alerts", to: "/alerts" }
        ]}
      />

      <div className="rounded-lg border border-border bg-panel p-4 shadow-soft">
        <div className="text-sm font-semibold">Events</div>
        <p className="mt-2 text-sm text-muted">
          Aqui vai entrar a tabela de eventos (KQL-like search, filtros, time range).
        </p>
      </div>
    </div>
  );
}
