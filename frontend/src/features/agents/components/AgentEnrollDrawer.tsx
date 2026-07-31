import { useCallback, useState } from "react";

import { Button } from "@/shared/components/Button";
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

interface AgentEnrollDrawerProps {
  open: boolean;
  onClose: () => void;
  isAdmin: boolean;
  controller: AgentEnrollmentController;
}

function formatExpiry(iso: string): string {
  const parsed = parseIso(iso);
  return parsed ? fmtDateTime(new Date(parsed)) : iso;
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

export default function AgentEnrollDrawer({ open, onClose, isAdmin, controller }: AgentEnrollDrawerProps) {
  const {
    onboarding,
    agentId,
    setAgentId,
    agentIdValid,
    profile,
    setProfile,
    architecture,
    setArchitecture,
    ticket,
    busy,
    error,
    canIssue,
    issueTicket,
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
      title="Enroll a new agent"
      description="Issue a single-use enrollment token and install the agent on the endpoint. The private key is generated on the endpoint and never leaves it."
      widthClassName="w-[880px]"
      headerLabel="Agent onboarding"
    >
      {!isAdmin ? (
        <InlineAlert tone="warning">Enrolling agents requires an administrator account.</InlineAlert>
      ) : (
        <div className="space-y-5">
          {error && <InlineAlert tone="danger">{error}</InlineAlert>}

          <Panel title="1. Identify the endpoint" compact>
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
                  Select the CPU architecture reported by the endpoint.
                </div>
              </div>
            </div>

            {!ticket && (
              <div className="mt-4 flex items-center gap-2">
                <Button variant="primary" size="md" disabled={!canIssue} onClick={() => void issueTicket()}>
                  {busy ? "Issuing…" : "Issue enrollment token"}
                </Button>
                {onboarding && (
                  <div className="text-[11px] text-muted-foreground">
                    Valid for {Math.round(onboarding.token_ttl_seconds / 60)} min, single use.
                  </div>
                )}
              </div>
            )}
          </Panel>

          <Panel title="2. Download the agent package" compact>
            {artifact && release ? (
              <div className="space-y-3 text-[12px] text-muted-foreground">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill variant="active">v{release.version}</StatusPill>
                  <StatusPill variant="neutral">{artifact.architecture}</StatusPill>
                  <a
                    href={artifact.download_url}
                    className="font-medium text-primary hover:underline"
                    target="_blank"
                    rel="noreferrer"
                  >
                    Download package
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
          </Panel>

          <Panel title="3. Install and enroll" compact>
            {!ticket ? (
              <div className="text-[12px] text-muted-foreground">
                Issue a token above to render the install command for this endpoint.
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill variant="active">token issued</StatusPill>
                  <StatusPill variant={ticket.profile === "managed" ? "warning" : "neutral"}>
                    {ticket.profile}
                  </StatusPill>
                  <div className="text-[11px] text-muted-foreground">
                    Expires {formatExpiry(ticket.expires_at)} • {ticket.max_uses} use
                  </div>
                </div>

                <InlineAlert tone="warning">
                  The token is shown once and is consumed at first contact. Paste it only when the installer prompts for it.
                </InlineAlert>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <FieldLabel>Enrollment token</FieldLabel>
                    <CopyButton value={ticket.bootstrap_token} label="Copy token" />
                  </div>
                  <pre className="overflow-x-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[11.5px] text-foreground">
                    {ticket.bootstrap_token}
                  </pre>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <FieldLabel>Install command</FieldLabel>
                    <CopyButton value={ticket.install_command} label="Copy command" />
                  </div>
                  <pre className="overflow-x-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[11.5px] text-foreground">
                    {ticket.install_command}
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

                <div className="grid gap-3 md:grid-cols-2">
                  <div className="space-y-1">
                    <FieldLabel>Agent API</FieldLabel>
                    <div className="font-mono text-[11.5px]">{ticket.api_url}</div>
                  </div>
                  <div className="space-y-1">
                    <FieldLabel>Enrollment endpoint</FieldLabel>
                    <div className="font-mono text-[11.5px]">{ticket.enroll_url}</div>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-1">
                  <Button variant="subtle" size="md" onClick={reset}>
                    Enroll another endpoint
                  </Button>
                </div>
              </div>
            )}
          </Panel>

          {onboarding && (
            <div className="text-[11px] text-muted-foreground">
              Wire protocol {onboarding.protocol_version} • server accepts {onboarding.min_supported_protocol}–
              {onboarding.max_supported_protocol}
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
}
