import { Card } from "@/shared/components/Card";
import { Link } from "react-router-dom";

export default function EventsPage() {
  return (
    <div className="space-y-6">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Telemetry</div>
        <h1 className="text-xl font-semibold">Events</h1>
        <p className="text-sm text-muted-foreground">
          Log de telemetria. A visão completa (sem limite) entra aqui quando você ativar paginação por cursor.
        </p>
      </div>

      <Card title="Event log" right={<Link to="/overview" className="text-primary hover:underline">Back to overview</Link>}>
        <div className="text-sm text-muted-foreground">
          Placeholder proposital. O próximo passo é “cursor pagination” e filtros (agent/time range/event_type).
        </div>
      </Card>
    </div>
  );
}
