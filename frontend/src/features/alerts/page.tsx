import { Card } from "@/shared/components/Card";
import { Link } from "react-router-dom";

export default function AlertsPage() {
  return (
    <div className="space-y-6">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Detection</div>
        <h1 className="text-xl font-semibold">Alerts</h1>
        <p className="text-sm text-muted-foreground">
          Alertas gerados por regras. A listagem paginada entra aqui.
        </p>
      </div>

      <Card title="Alert queue" right={<Link to="/overview" className="text-primary hover:underline">Back to overview</Link>}>
        <div className="text-sm text-muted-foreground">
          Placeholder proposital. Próximo passo: paginação por cursor, severidade, rule_id e detalhes.
        </div>
      </Card>
    </div>
  );
}
