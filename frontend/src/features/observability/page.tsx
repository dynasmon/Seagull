import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";

import ObservabilitySection from "./components/ObservabilitySection";
import ObservabilityToolbar from "./components/ObservabilityToolbar";
import StatBand from "./components/StatBand";
import { useObservabilityModel } from "./hooks/useObservabilityModel";
import { SECTIONS } from "./lib/panels";

export default function ObservabilityPage() {
  const model = useObservabilityModel();

  if (!model.isAdmin) {
    return (
      <Panel>
        <div className="py-12">
          <EmptyState
            title="Administrator access required"
            description="Platform observability metrics are restricted to administrators."
          />
        </div>
      </Panel>
    );
  }

  if (model.initializing) {
    return <Loading label="Loading observability metrics…" />;
  }

  const available = Boolean(model.status?.available);
  const disabled = model.status ? !model.status.enabled : false;

  return (
    <div className="space-y-6 pb-16">
      <ObservabilityToolbar
        status={model.status}
        rangePresetId={model.rangePresetId}
        onRangeChange={model.setRangePresetId}
        onRefresh={model.live.refreshNow}
        refreshing={model.live.state.isRefreshing}
        live={model.live.state.isLive}
        lastUpdated={model.live.state.lastUpdatedAt}
      />

      {model.statusError ? (
        <div className="rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger" role="alert">
          {model.statusError}
        </div>
      ) : null}

      {!available ? (
        <Panel>
          <div className="py-12">
            <EmptyState
              title={disabled ? "Prometheus integration disabled" : "Prometheus unreachable"}
              description={
                disabled
                  ? "Server-side Prometheus querying is turned off (SEAGULL_PROMETHEUS_ENABLED). Metrics are still scraped, but this view has no data source."
                  : "The backend cannot reach the internal Prometheus service right now. Metrics will appear automatically once the connection recovers."
              }
            />
          </div>
        </Panel>
      ) : (
        <>
          <StatBand envelopes={model.envelopes} />
          {SECTIONS.map((section) => (
            <ObservabilitySection
              key={section.id}
              section={section}
              envelopes={model.envelopes}
              available={available}
            />
          ))}
        </>
      )}
    </div>
  );
}
