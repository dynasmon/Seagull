import type { MouseEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  EuiButtonIcon,
  EuiFieldSearch,
  EuiHeader,
  EuiHeaderBreadcrumbs,
  EuiHeaderSection,
  EuiHeaderSectionItem,
  EuiHeaderSectionItemButton,
  EuiIcon,
  EuiText,
  type EuiBreadcrumb,
} from "@elastic/eui";

import { resolveRouteMeta } from "@/layout/navigation";
import { useTheme } from "@/app/providers";
import { useAuth } from "@/features/auth/context";

export default function TopBar({
  onToggleNavigation,
  onToggleCompact,
  compact,
  navigationOpen,
}: {
  onToggleNavigation: () => void;
  onToggleCompact: () => void;
  compact: boolean;
  navigationOpen?: boolean;
}) {
  const { theme, toggleTheme } = useTheme();
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const meta = resolveRouteMeta(location.pathname);

  const breadcrumbs: EuiBreadcrumb[] = meta.breadcrumbs.map((crumb, idx) => {
    const isLast = idx === meta.breadcrumbs.length - 1;
    return {
      text: crumb.label,
      href: !isLast && crumb.to ? crumb.to : undefined,
      onClick:
        !isLast && crumb.to
          ? (e: MouseEvent) => {
              e.preventDefault();
              navigate(crumb.to as string);
            }
          : undefined,
    };
  });

  return (
    <EuiHeader position="static" aria-label="Top bar">
      <EuiHeaderSection side="left">
        <EuiHeaderSectionItem className="lg:hidden">
          <EuiHeaderSectionItemButton
            aria-label={navigationOpen ? "Close navigation" : "Open navigation"}
            aria-controls="primary-navigation"
            aria-expanded={navigationOpen}
            onClick={onToggleNavigation}
          >
            <EuiIcon type="menu" />
          </EuiHeaderSectionItemButton>
        </EuiHeaderSectionItem>

        <EuiHeaderSectionItem className="hidden lg:flex">
          <EuiHeaderSectionItemButton
            aria-label={compact ? "Expand sidebar" : "Collapse sidebar"}
            onClick={onToggleCompact}
          >
            <EuiIcon type="menuLeft" />
          </EuiHeaderSectionItemButton>
        </EuiHeaderSectionItem>

        <EuiHeaderBreadcrumbs breadcrumbs={breadcrumbs} aria-label="Breadcrumb" />
      </EuiHeaderSection>

      <EuiHeaderSection side="right">
        <EuiHeaderSectionItem className="hidden xl:flex">
          <div style={{ width: 240 }}>
            <EuiFieldSearch placeholder="Search agents, alerts, hosts…" aria-label="Search" compressed />
          </div>
        </EuiHeaderSectionItem>

        {user ? (
          <EuiHeaderSectionItem className="hidden md:flex">
            <EuiText size="xs" color="subdued">
              <span>
                <strong>{user.username}</strong>
                {user.role ? ` · ${user.role}` : ""}
              </span>
            </EuiText>
          </EuiHeaderSectionItem>
        ) : null}

        <EuiHeaderSectionItem>
          <EuiButtonIcon
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            iconType={theme === "dark" ? "sun" : "moon"}
            color="text"
            display="empty"
            onClick={toggleTheme}
          />
        </EuiHeaderSectionItem>

        <EuiHeaderSectionItem>
          <EuiButtonIcon aria-label="Sign out" iconType="exit" color="text" display="empty" onClick={logout} />
        </EuiHeaderSectionItem>
      </EuiHeaderSection>
    </EuiHeader>
  );
}
