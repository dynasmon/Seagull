import type { ReactNode } from "react";
import {
  EuiBadge,
  EuiBetaBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHealth,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from "@elastic/eui";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";

function ParityRow({ label, eui, current }: { label: string; eui: ReactNode; current: ReactNode }) {
  return (
    <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false}>
      <EuiFlexItem grow={false} style={{ width: 110 }}>
        <EuiText size="xs"><strong>{label}</strong></EuiText>
      </EuiFlexItem>
      <EuiFlexItem>
        <div className="flex flex-wrap items-center gap-2">{eui}</div>
      </EuiFlexItem>
      <EuiFlexItem>
        <div className="flex flex-wrap items-center gap-2">{current}</div>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
}

export default function PrimitivesDemo() {
  return (
    <EuiPanel hasBorder paddingSize="l">
      <EuiTitle size="xs"><h3>Primitive parity — EUI (middle) vs current shared primitives (right)</h3></EuiTitle>
      <EuiSpacer size="m" />

      <ParityRow
        label="Buttons"
        eui={
          <>
            <EuiButton size="s" fill>Primary</EuiButton>
            <EuiButton size="s">Secondary</EuiButton>
            <EuiButtonEmpty size="s">Ghost</EuiButtonEmpty>
            <EuiButton size="s" color="danger">Danger</EuiButton>
            <EuiButtonIcon iconType="gear" aria-label="Settings" />
          </>
        }
        current={
          <>
            <Button variant="primary" size="sm">Primary</Button>
            <Button variant="secondary" size="sm">Secondary</Button>
            <Button variant="ghost" size="sm">Ghost</Button>
            <Button variant="danger" size="sm">Danger</Button>
          </>
        }
      />
      <EuiSpacer size="s" />

      <ParityRow
        label="Severity"
        eui={
          <>
            <EuiBadge color="danger">Critical</EuiBadge>
            <EuiBadge color="warning">High</EuiBadge>
            <EuiBadge color="#F5A700">Medium</EuiBadge>
            <EuiBadge color="primary">Low</EuiBadge>
          </>
        }
        current={
          <>
            <SeverityPill variant="critical" withDot>Critical</SeverityPill>
            <SeverityPill variant="high" withDot>High</SeverityPill>
            <SeverityPill variant="medium" withDot>Medium</SeverityPill>
            <SeverityPill variant="low" withDot>Low</SeverityPill>
          </>
        }
      />
      <EuiSpacer size="s" />

      <ParityRow
        label="Status"
        eui={
          <>
            <EuiHealth color="success">Active</EuiHealth>
            <EuiHealth color="warning">Pending</EuiHealth>
            <EuiHealth color="danger">Revoked</EuiHealth>
            <EuiHealth color="subdued">Inactive</EuiHealth>
          </>
        }
        current={
          <>
            <StatusPill variant="active" withDot>Active</StatusPill>
            <StatusPill variant="pending" withDot>Pending</StatusPill>
            <StatusPill variant="danger" withDot>Revoked</StatusPill>
            <StatusPill variant="inactive" withDot>Inactive</StatusPill>
          </>
        }
      />
      <EuiSpacer size="s" />

      <ParityRow
        label="Tags"
        eui={
          <>
            <EuiBadge>prod</EuiBadge>
            <EuiBadge color="hollow">edge</EuiBadge>
            <EuiBetaBadge label="Beta" size="s" />
          </>
        }
        current={
          <>
            <Badge variant="neutral">prod</Badge>
            <Badge variant="info">edge</Badge>
          </>
        }
      />
    </EuiPanel>
  );
}
