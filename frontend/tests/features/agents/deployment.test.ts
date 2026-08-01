import { describe, expect, it } from "vitest";

import {
  canIssueTicket,
  installerSizeBytes,
  isValidAgentId,
  packageFor,
  ticketRequestFrom,
  toggleCollector,
} from "@/features/agents/lib/deployment";
import type { AgentPackageState } from "@/features/agents/types";

const CATALOG = ["authlog", "proc", "proc_exec", "fim", "scan", "ddos", "l7", "lateral", "syscollector", "vuln"];

const PACKAGES: AgentPackageState[] = [
  {
    architecture: "amd64",
    filename: "seagull-agent_0.1.0_linux_amd64.tar.gz",
    sha256: "a".repeat(64),
    size_bytes: 3924527,
    cached: true,
  },
  {
    architecture: "arm64",
    filename: "seagull-agent_0.1.0_linux_arm64.tar.gz",
    sha256: "b".repeat(64),
    size_bytes: 3550924,
    cached: false,
  },
];

const TARGET = {
  agentId: "web-01",
  profile: "sensor" as const,
  architecture: "amd64" as const,
  sources: ["authlog", "proc"],
};

describe("agent identifiers", () => {
  it("accepts what the platform accepts", () => {
    expect(isValidAgentId("web-01")).toBe(true);
    expect(isValidAgentId("  web.01_a  ")).toBe(true);
    expect(isValidAgentId("a".repeat(64))).toBe(true);
  });

  it("rejects what the platform rejects", () => {
    expect(isValidAgentId("")).toBe(false);
    expect(isValidAgentId("../etc/passwd")).toBe(false);
    expect(isValidAgentId("-leading-dash")).toBe(false);
    expect(isValidAgentId("has space")).toBe(false);
    expect(isValidAgentId("a".repeat(65))).toBe(false);
  });
});

describe("collector selection", () => {
  it("adds and removes a collector", () => {
    expect(toggleCollector(["authlog"], "fim", CATALOG)).toEqual(["authlog", "fim"]);
    expect(toggleCollector(["authlog", "fim"], "authlog", CATALOG)).toEqual(["fim"]);
  });

  it("keeps the catalog order whatever order the operator clicks in", () => {
    const selected = ["vuln", "authlog"].reduce(
      (current, name) => toggleCollector(current, name, CATALOG),
      [] as string[],
    );
    expect(toggleCollector(selected, "fim", CATALOG)).toEqual(["authlog", "fim", "vuln"]);
  });

  it("drops a collector the platform no longer publishes", () => {
    expect(toggleCollector(["authlog", "retired"], "fim", CATALOG)).toEqual(["authlog", "fim"]);
  });
});

describe("deployment readiness", () => {
  it("requires an administrator, an identifier and at least one collector", () => {
    expect(canIssueTicket(TARGET, { isAdmin: true, busy: false })).toBe(true);
    expect(canIssueTicket(TARGET, { isAdmin: false, busy: false })).toBe(false);
    expect(canIssueTicket(TARGET, { isAdmin: true, busy: true })).toBe(false);
    expect(canIssueTicket({ ...TARGET, sources: [] }, { isAdmin: true, busy: false })).toBe(false);
    expect(canIssueTicket({ ...TARGET, agentId: "  " }, { isAdmin: true, busy: false })).toBe(false);
  });

  it("trims the identifier before asking the platform for a ticket", () => {
    expect(ticketRequestFrom({ ...TARGET, agentId: "  web-01  " })).toEqual({
      agent_id: "web-01",
      profile: "sensor",
      architecture: "amd64",
      sources: ["authlog", "proc"],
    });
  });
});

describe("package availability", () => {
  it("reports the package of the selected architecture", () => {
    expect(packageFor(PACKAGES, "amd64")?.cached).toBe(true);
    expect(packageFor(PACKAGES, "arm64")?.cached).toBe(false);
    expect(packageFor([], "amd64")).toBeNull();
  });

  it("estimates the installer size from the embedded package", () => {
    expect(installerSizeBytes(3924527)).toBe(5232703);
  });
});
