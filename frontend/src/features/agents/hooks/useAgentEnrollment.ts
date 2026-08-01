import { useCallback, useEffect, useMemo, useState } from "react";

import { getErrorMessage } from "@/shared/lib/errors";

import { createEnrollmentTicket, downloadAgentInstaller, getAgentOnboarding, syncAgentPackages } from "../api";
import { canIssueTicket, isValidAgentId, packageFor, ticketRequestFrom, toggleCollector } from "../lib/deployment";
import type {
  AgentArchitecture,
  AgentEnrollmentTicket,
  AgentOnboardingInfo,
  AgentPackageState,
  AgentProfile,
} from "../types";

interface UseAgentEnrollmentProps {
  open: boolean;
  isAdmin: boolean;
  onEnrolled?: () => void;
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function useAgentEnrollment({ open, isAdmin, onEnrolled }: UseAgentEnrollmentProps) {
  const [onboarding, setOnboarding] = useState<AgentOnboardingInfo | null>(null);
  const [packages, setPackages] = useState<AgentPackageState[]>([]);
  const [agentId, setAgentId] = useState("");
  const [profile, setProfile] = useState<AgentProfile>("sensor");
  const [architecture, setArchitecture] = useState<AgentArchitecture>("amd64");
  const [sources, setSources] = useState<string[]>([]);
  const [ticket, setTicket] = useState<AgentEnrollmentTicket | null>(null);
  const [busy, setBusy] = useState(false);
  const [preparing, setPreparing] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !isAdmin) return;
    let cancelled = false;
    getAgentOnboarding()
      .then((info) => {
        if (cancelled) return;
        setOnboarding(info);
        setPackages(info.packages);
        setProfile((info.default_profile === "managed" ? "managed" : "sensor") as AgentProfile);
        setArchitecture(info.release.artifacts[0]?.architecture ?? "amd64");
        setSources(info.default_collectors);
      })
      .catch((err) => {
        if (!cancelled) setError(getErrorMessage(err, "Failed to load onboarding settings"));
      });
    return () => {
      cancelled = true;
    };
  }, [open, isAdmin]);

  const reset = useCallback(() => {
    setAgentId("");
    setTicket(null);
    setError(null);
    setDownloaded(false);
    setProfile((onboarding?.default_profile === "managed" ? "managed" : "sensor") as AgentProfile);
    setArchitecture(onboarding?.release.artifacts[0]?.architecture ?? "amd64");
    setSources(onboarding?.default_collectors ?? []);
  }, [onboarding]);

  const toggleSource = useCallback(
    (name: string) => {
      setSources((current) => toggleCollector(current, name, onboarding?.collectors ?? current));
    },
    [onboarding],
  );

  const selectedPackage = useMemo(() => packageFor(packages, architecture), [packages, architecture]);

  const target = useMemo(
    () => ({ agentId, profile, architecture, sources }),
    [agentId, profile, architecture, sources],
  );
  const canIssue = canIssueTicket(target, { isAdmin, busy });

  const issueTicket = useCallback(async () => {
    if (!canIssue) return;
    setBusy(true);
    setError(null);
    try {
      const created = await createEnrollmentTicket(ticketRequestFrom(target));
      setTicket(created);
      setDownloaded(false);
      onEnrolled?.();
    } catch (err) {
      setError(getErrorMessage(err, "Failed to issue enrollment token"));
    } finally {
      setBusy(false);
    }
  }, [canIssue, target, onEnrolled]);

  const preparePackages = useCallback(async () => {
    setPreparing(true);
    setError(null);
    try {
      const synced = await syncAgentPackages();
      setPackages(synced.packages);
    } catch (err) {
      setError(getErrorMessage(err, "Failed to prepare the agent packages"));
    } finally {
      setPreparing(false);
    }
  }, []);

  const downloadInstaller = useCallback(async () => {
    if (!ticket) return;
    setDownloading(true);
    setError(null);
    try {
      const blob = await downloadAgentInstaller(ticket.bootstrap_token);
      saveBlob(blob, ticket.installer_filename);
      setDownloaded(true);
    } catch (err) {
      setError(getErrorMessage(err, "Failed to build the pre-configured installer"));
    } finally {
      setDownloading(false);
    }
  }, [ticket]);

  return {
    onboarding,
    packages,
    selectedPackage,
    agentId,
    setAgentId,
    agentIdValid: agentId.trim().length === 0 || isValidAgentId(agentId),
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
  };
}

export type AgentEnrollmentController = ReturnType<typeof useAgentEnrollment>;
