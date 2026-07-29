import { useCallback, useEffect, useState } from "react";

import { getErrorMessage } from "@/shared/lib/errors";

import { createEnrollmentTicket, getAgentOnboarding } from "../api";
import type { AgentEnrollmentTicket, AgentOnboardingInfo, AgentProfile } from "../types";

interface UseAgentEnrollmentProps {
  open: boolean;
  isAdmin: boolean;
  onEnrolled?: () => void;
}

export function useAgentEnrollment({ open, isAdmin, onEnrolled }: UseAgentEnrollmentProps) {
  const [onboarding, setOnboarding] = useState<AgentOnboardingInfo | null>(null);
  const [agentId, setAgentId] = useState("");
  const [profile, setProfile] = useState<AgentProfile>("sensor");
  const [ticket, setTicket] = useState<AgentEnrollmentTicket | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !isAdmin) return;
    let cancelled = false;
    getAgentOnboarding()
      .then((info) => {
        if (cancelled) return;
        setOnboarding(info);
        setProfile((info.default_profile === "managed" ? "managed" : "sensor") as AgentProfile);
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
    setProfile((onboarding?.default_profile === "managed" ? "managed" : "sensor") as AgentProfile);
  }, [onboarding]);

  const trimmedAgentId = agentId.trim();
  const agentIdValid = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(trimmedAgentId);
  const canIssue = isAdmin && agentIdValid && !busy;

  const issueTicket = useCallback(async () => {
    if (!canIssue) return;
    setBusy(true);
    setError(null);
    try {
      const created = await createEnrollmentTicket({ agent_id: trimmedAgentId, profile });
      setTicket(created);
      onEnrolled?.();
    } catch (err) {
      setError(getErrorMessage(err, "Failed to issue enrollment token"));
    } finally {
      setBusy(false);
    }
  }, [canIssue, trimmedAgentId, profile, onEnrolled]);

  return {
    onboarding,
    agentId,
    setAgentId,
    agentIdValid: trimmedAgentId.length === 0 || agentIdValid,
    profile,
    setProfile,
    ticket,
    busy,
    error,
    canIssue,
    issueTicket,
    reset,
  };
}

export type AgentEnrollmentController = ReturnType<typeof useAgentEnrollment>;
