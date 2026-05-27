import { countish } from "./inventoryParsers";

export function extractExtraDomainMetrics(extra: Record<string, any> | undefined | null): Array<{ key: string; value: string }> {
  const src = extra || {};
  const picks: Array<{ label: string; value: any }> = [
    { label: "processes", value: src.processes ?? src.runtime_processes ?? src.process_list },
    { label: "network_connections", value: src.network_connections ?? src.connections ?? src.net_connections },
    { label: "network_interfaces", value: src.network_interfaces ?? src.interfaces ?? src.net_ifaces },
    { label: "services", value: src.services ?? src.systemd_services ?? src.listening_services },
    { label: "users", value: src.users ?? src.identities ?? src.accounts },
    { label: "groups", value: src.groups ?? src.roles },
  ];

  return picks
    .map((item) => ({ key: item.label, n: countish(item.value) }))
    .filter((item) => item.n !== null)
    .map((item) => ({ key: item.key, value: String(item.n) }));
}
