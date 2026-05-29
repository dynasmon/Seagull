import type { MouseEvent } from "react";
import {
  EuiFieldSearch,
  EuiHeader,
  EuiHeaderLogo,
  EuiHeaderSectionItemButton,
  EuiIcon,
  EuiPanel,
  EuiSideNav,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from "@elastic/eui";

import { SOC_NAV_GROUPS } from "@/layout/navigation";

export default function ShellDemo() {
  const sideNavItems = SOC_NAV_GROUPS.map((group) => ({
    id: group.id,
    name: group.label,
    items: group.items.map((it) => ({
      id: it.id,
      name: it.label,
      href: `#${it.to}`,
      onClick: (e: MouseEvent) => e.preventDefault(),
    })),
  }));

  return (
    <EuiPanel hasBorder paddingSize="none">
      <div style={{ height: 520, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <EuiHeader
          theme="dark"
          sections={[
            {
              items: [<EuiHeaderLogo key="logo" iconType="logoSecurity">Seagull</EuiHeaderLogo>],
              breadcrumbs: [{ text: "Security" }, { text: "Overview" }],
            },
            {
              items: [
                <EuiFieldSearch key="search" placeholder="Search…" compressed />,
                <EuiHeaderSectionItemButton key="alerts" aria-label="Alerts" notification="3">
                  <EuiIcon type="bell" />
                </EuiHeaderSectionItemButton>,
              ],
            },
          ]}
        />
        <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
          <div style={{ width: 240, borderRight: "1px solid rgba(127,127,127,0.2)", overflowY: "auto", padding: 12 }}>
            <EuiSideNav items={sideNavItems} aria-label="SOC navigation" />
          </div>
          <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
            <EuiTitle size="s"><h2>Security Overview</h2></EuiTitle>
            <EuiText size="s" color="subdued">
              <p>EuiHeader + EuiSideNav fed by the real SOC_NAV_GROUPS model. Previews the Phase-2 Kibana-style shell.</p>
            </EuiText>
            <EuiSpacer />
            <EuiText size="s"><p>Content region scrolls independently inside this contained shell preview.</p></EuiText>
          </div>
        </div>
      </div>
    </EuiPanel>
  );
}
