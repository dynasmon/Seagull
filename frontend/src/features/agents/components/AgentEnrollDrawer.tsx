import { useCallback, useState } from "react";
import { EuiAccordion } from "@elastic/eui";

import { Button } from "@/shared/components/Button";
import { CheckboxField } from "@/shared/components/CheckboxField";
import Drawer from "@/shared/components/Drawer";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { StatusPill } from "@/shared/components/StatusPill";
import { TextInput } from "@/shared/components/TextInput";
import { copyTextToClipboard } from "@/shared/components/investigation/utils";

import { FieldLabel } from "./AgentsPageShared";
import type { AgentEnrollmentController } from "../hooks/useAgentEnrollment";
import type { AgentArchitecture, AgentProfile } from "../types";
import { fmtDateTime, parseIso } from "../lib/agentUtils";
import { installerSizeBytes } from "../lib/deployment";

interface AgentEnrollDrawerProps {
  open: boolean;
  onClose: () => void;
  isAdmin: boolean;
  controller: AgentEnrollmentController;
}

const COLLECTOR_SUMMARY: Record<string, string> = {
  authlog: "SSH and sudo authentication",
  proc: "Connection flows from /proc",
  proc_exec: "Process execution lineage",
  fim: "File integrity and persistence",
  scan: "Port-scan detection",
  ddos: "Volumetric and L7 floods",
  l7: "HTTP, DNS and TLS metadata",
  lateral: "Lateral-movement connections",
  syscollector: "OS and package inventory",
  vuln: "Vulnerability correlation",
};

function formatExpiry(iso: string): string {
  const parsed = parseIso(iso);
  return parsed ? fmtDateTime(new Date(parsed)) : iso;
}

function formatSize(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = useCallback(() => {
    void copyTextToClipboard(value).then((ok) => {
      setCopied(ok);
      if (ok) window.setTimeout(() => setCopied(false), 1500);
    });
  }, [value]);

  return (
    <Button variant="subtle" size="md" onClick={onCopy}>
      {copied ? "Copied" : label}
    </Button>
  );
}

function DownloadButton({ value, filename, label }: { value: string; filename: string; label: string }) {
  const onDownload = useCallback(() => {
    const url = URL.createObjectURL(new Blob([value], { type: "application/x-pem-file" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }, [value, filename]);

  return (
    <Button variant="subtle" size="md" onClick={onDownload}>
      {label}
    </Button>
  );
}

function CommandBlock({ command, label }: { command: string; label: string }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <FieldLabel>{label}</FieldLabel>
        <CopyButton value={command} label="Copy command" />
      </div>
      <pre className="overflow-x-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[11.5px] text-foreground">
        {command}
      </pre>
    </div>
  );
}

export default function AgentEnrollDrawer({ open, onClose, isAdmin, controller }: AgentEnrollDrawerProps) {
  const {
    onboarding,
    selectedPackage,
    agentId,
    setAgentId,
    agentIdValid,
    profile,
    setProfile,
    architecture,
    setArchitecture,
    sources,
    toggleSource,
    ticket,
    busy,
    preparing,
    downloading,
    downloaded,
    error,
    canIssue,
    issueTicket,
    preparePackages,
    downloadInstaller,
    reset,
  } = controller;

  const handleClose = useCallback(() => {
    reset();
    onClose();
  }, [reset, onClose]);
  const release = ticket?.release ?? onboarding?.release;
  const artifact = ticket?.artifact ?? release?.artifacts.find((value) => value.architecture === architecture);

  return (
    <Drawer
      open={open}
      onClose={handleClose}
      title="Deploy an agent"
      description="Configure the endpoint here, download an installer that already carries this platform's address, trust anchor and single-use enrollment token, then run one command on the endpoint."
      widthClassName="w-[880px]"
      headerLabel="Agent onboarding"
    >
      {!isAdmin ? (
        <InlineAlert tone="warning">Deploying agents requires an administrator account.</InlineAlert>
      ) : (
        <div className="space-y-5">
          {error && <InlineAlert tone="danger">{error}</InlineAlert>}

          {selectedPackage?.error && (
            <InlineAlert tone="danger">
              {selectedPackage.error}
            </InlineAlert>
          )}

          {selectedPackage && !selectedPackage.cached && !selectedPackage.error && (
            <InlineAlert tone="warning">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <span>
                  The {selectedPackage.architecture} package is not on this server yet. It is downloaded and verified
                  against its pinned digest on first use.
                </span>
                <Button variant="secondary" size="md" disabled={preparing} onClick={() => void preparePackages()}>
                  {preparing ? "Preparing…" : "Prepare now"}
                </Button>
              </div>
            </InlineAlert>
          )}

          <Panel title="1. Describe the endpoint" compact>
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-1.5">
                <FieldLabel>Agent id</FieldLabel>
                <TextInput
                  value={agentId}
                  onChange={(e) => setAgentId(e.target.value)}
                  placeholder="web-01"
                  error={!agentIdValid}
                  disabled={!!ticket}
                />
                <div className="text-[11px] text-muted-foreground">
                  Letters, digits, dot, dash and underscore. Stable across reinstalls.
                </div>
              </div>

              <div className="space-y-1.5">
                <FieldLabel>Security profile</FieldLabel>
                <SelectInput
                  value={profile}
                  onChange={(e) => setProfile(e.target.value as AgentProfile)}
                  disabled={!!ticket}
                >
                  <option value="sensor">sensor — telemetry only</option>
                  <option value="managed">managed — telemetry and response actions</option>
                </SelectInput>
                <div className="text-[11px] text-muted-foreground">
                  Sensor installations cannot execute response actions, on the server or on the endpoint.
                </div>
              </div>

              <div className="space-y-1.5">
                <FieldLabel>Architecture</FieldLabel>
                <SelectInput
                  value={architecture}
                  onChange={(e) => setArchitecture(e.target.value as AgentArchitecture)}
                  disabled={!!ticket}
                >
                  {onboarding?.release.artifacts.map((value) => (
                    <option key={value.architecture} value={value.architecture}>
                      Linux {value.architecture}
                    </option>
                  ))}
                </SelectInput>
                <div className="text-[11px] text-muted-foreground">
                  The installer refuses to run on a host that reports a different architecture.
                </div>
              </div>
            </div>

            <div className="mt-4 space-y-2">
              <FieldLabel>Collectors</FieldLabel>
              <div className="grid gap-x-4 gap-y-1.5 sm:grid-cols-2 lg:grid-cols-3">
                {(onboarding?.collectors ?? []).map((name) => (
                  <CheckboxField
                    key={name}
                    label={
                      <span className="text-[12px]">
                        <span className="font-mono">{name}</span>
                        <span className="text-muted-foreground"> — {COLLECTOR_SUMMARY[name] ?? "collector"}</span>
                      </span>
                    }
                    checked={sources.includes(name)}
                    onChange={() => toggleSource(name)}
                    disabled={!!ticket}
                  />
                ))}
              </div>
              <div className="text-[11px] text-muted-foreground">
                The endpoint is granted only the Linux capabilities the selected collectors require.
              </div>
            </div>

            {!ticket && (
              <div className="mt-4 flex items-center gap-2">
                <Button variant="primary" size="md" disabled={!canIssue} onClick={() => void issueTicket()}>
                  {busy ? "Generating…" : "Generate the installer"}
                </Button>
                {onboarding && (
                  <div className="text-[11px] text-muted-foreground">
                    The enrollment token is valid for {Math.round(onboarding.token_ttl_seconds / 60)} min and is
                    consumed on first contact.
                  </div>
                )}
              </div>
            )}
          </Panel>

          <Panel title="2. Install on the endpoint" compact>
            {!ticket ? (
              <div className="text-[12px] text-muted-foreground">
                Describe the endpoint above to build its installer.
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill variant="active">{ticket.agent_id}</StatusPill>
                  <StatusPill variant={ticket.profile === "managed" ? "warning" : "neutral"}>
                    {ticket.profile}
                  </StatusPill>
                  <StatusPill variant="neutral">
                    v{ticket.release.version} · {ticket.architecture}
                  </StatusPill>
                  <div className="text-[11px] text-muted-foreground">
                    Expires {formatExpiry(ticket.expires_at)}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <Button variant="primary" size="md" disabled={downloading} onClick={() => void downloadInstaller()}>
                    {downloading ? "Building…" : downloaded ? "Download again" : "Download the installer"}
                  </Button>
                  <div className="text-[11px] text-muted-foreground">
                    <span className="font-mono">{ticket.installer_filename}</span>
                    {selectedPackage ? ` · about ${formatSize(installerSizeBytes(selectedPackage.size_bytes))}` : ""}
                  </div>
                </div>

                <div className="text-[12px] text-muted-foreground">
                  Copy the file to {ticket.agent_id} and run it as root. It verifies its payload, resolves runtime
                  dependencies, installs the service and enrolls against{" "}
                  <span className="font-mono">{ticket.api_url}</span>.
                </div>

                <CommandBlock command={ticket.installer_command} label="On the endpoint" />

                <div className="space-y-2 border-t border-border pt-4">
                  <div className="text-[12px] text-muted-foreground">
                    When the endpoint can reach this portal directly, a single command does both steps.
                  </div>
                  <CommandBlock command={ticket.bootstrap_command} label="Fetch and install from the endpoint" />
                  <div className="text-[11px] text-muted-foreground">
                    The endpoint must trust this portal's TLS certificate. The command carries the single-use
                    enrollment token, so treat it as a secret.
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-1">
                  <Button variant="subtle" size="md" onClick={reset}>
                    Deploy another endpoint
                  </Button>
                </div>
              </div>
            )}
          </Panel>

          <EuiAccordion
            id="agent-manual-install"
            buttonContent={
              <span className="text-[12px] font-medium">Install from the upstream release instead</span>
            }
            paddingSize="none"
          >
            <div className="space-y-4 pt-3">
              <div className="text-[12px] text-muted-foreground">
                Use this path to verify the release provenance yourself, or when the platform cannot distribute the
                package. Every artifact is signed by the agent repository's release workflow.
              </div>

              {artifact && release ? (
                <div className="space-y-3 text-[12px] text-muted-foreground">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusPill variant="neutral">v{release.version}</StatusPill>
                    <a
                      href={artifact.download_url}
                      className="font-medium text-primary hover:underline"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Package
                    </a>
                    <a
                      href={artifact.sbom_url}
                      className="font-medium text-primary hover:underline"
                      target="_blank"
                      rel="noreferrer"
                    >
                      SBOM
                    </a>
                    <a
                      href={release.checksums_url}
                      className="font-medium text-primary hover:underline"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Checksums
                    </a>
                    <a
                      href={release.checksums_signature_url}
                      className="font-medium text-primary hover:underline"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Signature
                    </a>
                    <a
                      href={release.checksums_certificate_url}
                      className="font-medium text-primary hover:underline"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Signing certificate
                    </a>
                  </div>
                  <pre className="overflow-x-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[11.5px] text-foreground">
{`curl --fail --location --remote-name "${artifact.download_url}"
curl --fail --location --remote-name "${release.checksums_url}"
curl --fail --location --remote-name "${release.checksums_signature_url}"
curl --fail --location --remote-name "${release.checksums_certificate_url}"
cosign verify-blob \\
  --certificate SHA256SUMS.pem \\
  --signature SHA256SUMS.sig \\
  --certificate-identity "https://github.com/dynasmon/seagull-agent/.github/workflows/release.yml@refs/tags/${release.tag}" \\
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \\
  SHA256SUMS
sha256sum --check SHA256SUMS --ignore-missing
tar xzf "${artifact.filename}"
cd "${artifact.filename.replace(/\.tar\.gz$/, "")}"`}
                  </pre>
                </div>
              ) : (
                <div className="text-[12px] text-muted-foreground">Loading the supported release…</div>
              )}

              {ticket ? (
                <div className="space-y-4">
                  <CommandBlock command={ticket.install_command} label="Install command" />

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <FieldLabel>Enrollment token</FieldLabel>
                      <CopyButton value={ticket.bootstrap_token} label="Copy token" />
                    </div>
                    <pre className="overflow-x-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[11.5px] text-foreground">
                      {ticket.bootstrap_token}
                    </pre>
                  </div>

                  {ticket.server_ca_required && (
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <FieldLabel>Server certificate authority</FieldLabel>
                        {ticket.server_ca_pem && (
                          <DownloadButton value={ticket.server_ca_pem} filename="server-ca.crt" label="Download CA" />
                        )}
                      </div>
                      {ticket.server_ca_fingerprint_sha256 && (
                        <div className="font-mono text-[11px] text-muted-foreground/80">
                          sha256: {ticket.server_ca_fingerprint_sha256}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-[12px] text-muted-foreground">
                  Generate an installer above to render the manual install command for this endpoint.
                </div>
              )}
            </div>
          </EuiAccordion>

          {onboarding && (
            <div className="text-[11px] text-muted-foreground">
              Wire protocol {onboarding.protocol_version} • server accepts {onboarding.min_supported_protocol}–
              {onboarding.max_supported_protocol}
              {selectedPackage?.sha256 ? (
                <>
                  {" "}
                  • package sha256 <span className="font-mono">{selectedPackage.sha256.slice(0, 16)}…</span>
                </>
              ) : null}
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
}
