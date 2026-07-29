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
import type { AgentProfile } from "../types";
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

export default function AgentEnrollDrawer({ open, onClose, isAdmin, controller }: AgentEnrollDrawerProps) {
  const {
    onboarding,
    agentId,
    setAgentId,
    agentIdValid,
    profile,
    setProfile,
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
            <div className="grid gap-4 md:grid-cols-2">
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
            <div className="space-y-2 text-[12px] text-muted-foreground">
              <div>
                Copy the release tarball for the endpoint architecture onto the host and unpack it. The package carries the
                binary, the systemd unit and the installer, so the host needs neither this repository nor a Go toolchain.
              </div>
              <pre className="overflow-x-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[11.5px] text-foreground">
{`tar xzf seagull-agent_<version>_linux_amd64.tar.gz
cd seagull-agent_<version>_linux_amd64
sha256sum -c ../SHA256SUMS --ignore-missing`}
              </pre>
            </div>
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
                  The token is shown once and is consumed at first contact. Treat it as a secret.
                </InlineAlert>

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
                    <FieldLabel>Server certificate authority</FieldLabel>
                    <div className="text-[11.5px] text-muted-foreground">
                      This deployment uses a private authority. Copy <span className="font-mono">secrets/pki/server-ca.crt</span>{" "}
                      to the endpoint as <span className="font-mono">server-ca.crt</span> before running the installer.
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
