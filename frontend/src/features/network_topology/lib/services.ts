export type ServiceCategory =
  | "web"
  | "database"
  | "remote"
  | "infrastructure"
  | "mail"
  | "file"
  | "monitoring"
  | "security"
  | "messaging"
  | "container"
  | "other";

export type ServiceInfo = {
  name: string;
  category: ServiceCategory;
};

export const SERVICE_CATEGORY_META: Record<
  ServiceCategory,
  { label: string; color: string; bg: string; order: number }
> = {
  web:            { label: "Web",            color: "#60A5FA", bg: "rgba(96,165,250,0.12)",  order: 0 },
  database:       { label: "Database",       color: "#A78BFA", bg: "rgba(167,139,250,0.12)", order: 1 },
  remote:         { label: "Remote Access",  color: "#F87171", bg: "rgba(248,113,113,0.12)", order: 2 },
  infrastructure: { label: "Infrastructure", color: "#FBBF24", bg: "rgba(251,191,36,0.12)",  order: 3 },
  mail:           { label: "Mail",           color: "#34D399", bg: "rgba(52,211,153,0.12)",  order: 4 },
  file:           { label: "File Share",     color: "#F97316", bg: "rgba(249,115,22,0.12)",  order: 5 },
  monitoring:     { label: "Monitoring",     color: "#22D3EE", bg: "rgba(34,211,238,0.12)",  order: 6 },
  security:       { label: "Security",       color: "#FB923C", bg: "rgba(251,146,60,0.12)",  order: 7 },
  messaging:      { label: "Messaging",      color: "#E879F9", bg: "rgba(232,121,249,0.12)", order: 8 },
  container:      { label: "Container",      color: "#38BDF8", bg: "rgba(56,189,248,0.12)",  order: 9 },
  other:          { label: "Other",          color: "#9CA3AF", bg: "rgba(156,163,175,0.08)", order: 10 },
};

export const CATEGORY_ORDER: ServiceCategory[] = [
  "web", "database", "remote", "infrastructure", "mail",
  "file", "monitoring", "security", "messaging", "container", "other",
];

const PORT_MAP: Record<number, ServiceInfo> = {
  20:    { name: "FTP Data",         category: "file" },
  21:    { name: "FTP",              category: "file" },
  22:    { name: "SSH",              category: "remote" },
  23:    { name: "Telnet",           category: "remote" },
  25:    { name: "SMTP",             category: "mail" },
  53:    { name: "DNS",              category: "infrastructure" },
  67:    { name: "DHCP",             category: "infrastructure" },
  68:    { name: "DHCP",             category: "infrastructure" },
  69:    { name: "TFTP",             category: "file" },
  79:    { name: "Finger",           category: "infrastructure" },
  80:    { name: "HTTP",             category: "web" },
  88:    { name: "Kerberos",         category: "security" },
  102:   { name: "ISO-TSAP",         category: "infrastructure" },
  110:   { name: "POP3",             category: "mail" },
  111:   { name: "RPC",              category: "infrastructure" },
  119:   { name: "NNTP",             category: "messaging" },
  123:   { name: "NTP",              category: "infrastructure" },
  135:   { name: "MSRPC",            category: "infrastructure" },
  137:   { name: "NetBIOS-NS",       category: "infrastructure" },
  138:   { name: "NetBIOS-DGM",      category: "infrastructure" },
  139:   { name: "SMB",              category: "file" },
  143:   { name: "IMAP",             category: "mail" },
  161:   { name: "SNMP",             category: "monitoring" },
  162:   { name: "SNMP Trap",        category: "monitoring" },
  179:   { name: "BGP",              category: "infrastructure" },
  194:   { name: "IRC",              category: "messaging" },
  389:   { name: "LDAP",             category: "security" },
  443:   { name: "HTTPS",            category: "web" },
  445:   { name: "SMB",              category: "file" },
  465:   { name: "SMTPS",            category: "mail" },
  500:   { name: "IKE/IPSec",        category: "security" },
  514:   { name: "Syslog",           category: "monitoring" },
  515:   { name: "LPD Print",        category: "infrastructure" },
  587:   { name: "SMTP Submit",      category: "mail" },
  631:   { name: "IPP",              category: "infrastructure" },
  636:   { name: "LDAPS",            category: "security" },
  993:   { name: "IMAPS",            category: "mail" },
  995:   { name: "POP3S",            category: "mail" },
  1080:  { name: "SOCKS",            category: "infrastructure" },
  1194:  { name: "OpenVPN",          category: "security" },
  1433:  { name: "MSSQL",            category: "database" },
  1521:  { name: "Oracle DB",        category: "database" },
  1883:  { name: "MQTT",             category: "messaging" },
  2049:  { name: "NFS",              category: "file" },
  2181:  { name: "ZooKeeper",        category: "infrastructure" },
  2375:  { name: "Docker",           category: "container" },
  2376:  { name: "Docker TLS",       category: "container" },
  2379:  { name: "etcd",             category: "infrastructure" },
  2380:  { name: "etcd Peer",        category: "infrastructure" },
  3000:  { name: "Grafana",          category: "monitoring" },
  3306:  { name: "MySQL",            category: "database" },
  3389:  { name: "RDP",              category: "remote" },
  4443:  { name: "HTTPS Alt",        category: "web" },
  4505:  { name: "Salt Master",      category: "infrastructure" },
  4506:  { name: "Salt Minion",      category: "infrastructure" },
  5000:  { name: "Dev HTTP",         category: "web" },
  5432:  { name: "PostgreSQL",       category: "database" },
  5601:  { name: "Kibana",           category: "monitoring" },
  5672:  { name: "RabbitMQ",         category: "messaging" },
  5900:  { name: "VNC",              category: "remote" },
  5901:  { name: "VNC-1",            category: "remote" },
  5985:  { name: "WinRM",            category: "remote" },
  5986:  { name: "WinRM TLS",        category: "remote" },
  6379:  { name: "Redis",            category: "database" },
  6443:  { name: "Kubernetes API",   category: "container" },
  7001:  { name: "Cassandra",        category: "database" },
  7199:  { name: "Cassandra JMX",    category: "database" },
  7474:  { name: "Neo4j",            category: "database" },
  7687:  { name: "Neo4j Bolt",       category: "database" },
  8080:  { name: "HTTP Alt",         category: "web" },
  8443:  { name: "HTTPS Alt",        category: "web" },
  8888:  { name: "Jupyter",          category: "monitoring" },
  9000:  { name: "SonarQube",        category: "monitoring" },
  9090:  { name: "Prometheus",       category: "monitoring" },
  9092:  { name: "Kafka",            category: "messaging" },
  9200:  { name: "Elasticsearch",    category: "database" },
  9300:  { name: "ES Cluster",       category: "database" },
  9418:  { name: "Git",              category: "file" },
  10250: { name: "Kubelet",          category: "container" },
  10255: { name: "Kubelet RO",       category: "container" },
  11211: { name: "Memcached",        category: "database" },
  15672: { name: "RabbitMQ UI",      category: "messaging" },
  15671: { name: "RabbitMQ TLS",     category: "messaging" },
  16443: { name: "MicroK8s API",     category: "container" },
  27017: { name: "MongoDB",          category: "database" },
  27018: { name: "MongoDB Shard",    category: "database" },
  27019: { name: "MongoDB Config",   category: "database" },
  28017: { name: "MongoDB Web",      category: "database" },
  50000: { name: "Jenkins",          category: "monitoring" },
  51820: { name: "WireGuard",        category: "security" },
  61616: { name: "ActiveMQ",         category: "messaging" },
};

const APP_PROTO_MAP: Record<string, ServiceInfo> = {
  http:     { name: "HTTP",        category: "web" },
  https:    { name: "HTTPS",       category: "web" },
  tls:      { name: "TLS",         category: "web" },
  dns:      { name: "DNS",         category: "infrastructure" },
  ssh:      { name: "SSH",         category: "remote" },
  ftp:      { name: "FTP",         category: "file" },
  smtp:     { name: "SMTP",        category: "mail" },
  imap:     { name: "IMAP",        category: "mail" },
  pop3:     { name: "POP3",        category: "mail" },
  ntp:      { name: "NTP",         category: "infrastructure" },
  snmp:     { name: "SNMP",        category: "monitoring" },
  smb:      { name: "SMB",         category: "file" },
  rdp:      { name: "RDP",         category: "remote" },
  ldap:     { name: "LDAP",        category: "security" },
  dcerpc:   { name: "MSRPC",       category: "infrastructure" },
  dhcp:     { name: "DHCP",        category: "infrastructure" },
  mqtt:     { name: "MQTT",        category: "messaging" },
  modbus:   { name: "Modbus",      category: "infrastructure" },
  dnp3:     { name: "DNP3",        category: "infrastructure" },
  krb5:     { name: "Kerberos",    category: "security" },
  tftp:     { name: "TFTP",        category: "file" },
  telnet:   { name: "Telnet",      category: "remote" },
  mysql:    { name: "MySQL",       category: "database" },
  pgsql:    { name: "PostgreSQL",  category: "database" },
  redis:    { name: "Redis",       category: "database" },
  mongodb:  { name: "MongoDB",     category: "database" },
  nfs:      { name: "NFS",         category: "file" },
  bgp:      { name: "BGP",         category: "infrastructure" },
  irc:      { name: "IRC",         category: "messaging" },
};

export function resolveServiceInfo(
  port: number | null,
  _protocol: string | null,
  metadata?: Record<string, unknown>,
): ServiceInfo {
  if (metadata?.service_name) {
    return {
      name: String(metadata.service_name),
      category: (String(metadata.service_category ?? "other")) as ServiceCategory,
    };
  }
  const appProto = String(metadata?.app_proto ?? "").toLowerCase().trim();
  if (appProto && appProto !== "unknown" && appProto !== "failed" && appProto !== "n/a") {
    const match = APP_PROTO_MAP[appProto];
    if (match) return match;
    return { name: appProto.toUpperCase(), category: "other" };
  }
  if (port && PORT_MAP[port]) return PORT_MAP[port];
  if (port) return { name: `Port ${port}`, category: "other" };
  return { name: "Unknown", category: "other" };
}

export function fmtFlows(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}
