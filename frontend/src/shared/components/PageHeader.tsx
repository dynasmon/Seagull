import type { MouseEvent, ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { EuiPageHeader } from "@elastic/eui";
import type { EuiBreadcrumb, EuiTabProps } from "@elastic/eui";

export type PageHeaderTab = { label: string; to: string; end?: boolean };
export type PageHeaderBreadcrumb = string | { label: string; to?: string };

function asBreadcrumbItem(item: PageHeaderBreadcrumb): { label: string; to?: string } {
  if (typeof item === "string") return { label: item };
  return item;
}

function shouldNavigateClientSide(event: MouseEvent<HTMLElement>): boolean {
  return !event.defaultPrevented && event.button === 0 && !event.metaKey && !event.altKey && !event.ctrlKey && !event.shiftKey;
}

function computeEnd(tab: PageHeaderTab, tabs: PageHeaderTab[]): boolean {
  if (typeof tab.end === "boolean") return tab.end;
  const base = (tab.to || "/").replace(/\/+$/g, "") || "/";
  const prefix = base === "/" ? "/" : `${base}/`;
  const hasChild = tabs.some((other) => other.to !== tab.to && (other.to || "").startsWith(prefix));
  return hasChild;
}

function isTabActive(pathname: string, tab: PageHeaderTab, tabs: PageHeaderTab[]): boolean {
  if (computeEnd(tab, tabs)) return pathname === tab.to;
  return pathname === tab.to || pathname.startsWith(`${tab.to}/`);
}

export function PageHeader({
  title,
  breadcrumb,
  description,
  tabs,
  toolbarRight,
}: {
  title: string;
  breadcrumb?: PageHeaderBreadcrumb[];
  description?: string | ReactNode;
  tabs?: PageHeaderTab[];
  toolbarRight?: ReactNode;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const computedTabs = tabs ?? [];

  const breadcrumbs: EuiBreadcrumb[] | undefined = breadcrumb?.map((entry, idx) => {
    const item = asBreadcrumbItem(entry);
    const isLast = idx === breadcrumb.length - 1;
    const isLink = Boolean(item.to && !isLast);
    return {
      text: item.label,
      href: isLink ? item.to : undefined,
      onClick: isLink
        ? (event: MouseEvent<HTMLAnchorElement>) => {
            if (shouldNavigateClientSide(event)) {
              event.preventDefault();
              navigate(item.to as string);
            }
          }
        : undefined,
    };
  });

  const euiTabs: Array<EuiTabProps & { label: ReactNode }> | undefined =
    computedTabs.length > 0
      ? computedTabs.map((tab) => ({
          label: tab.label,
          href: tab.to,
          isSelected: isTabActive(location.pathname, tab, computedTabs),
          onClick: (event: MouseEvent<HTMLAnchorElement>) => {
            if (shouldNavigateClientSide(event)) {
              event.preventDefault();
              navigate(tab.to);
            }
          },
        }))
      : undefined;

  return (
    <EuiPageHeader
      className="ui-section-shell mb-5 overflow-hidden"
      color="plain"
      paddingSize="m"
      bottomBorder={Boolean(euiTabs)}
      pageTitle={title}
      description={description}
      breadcrumbs={breadcrumbs}
      breadcrumbProps={breadcrumbs ? { responsive: false } : undefined}
      tabs={euiTabs}
      tabsProps={euiTabs ? { bottomBorder: false } : undefined}
      rightSideItems={toolbarRight ? [toolbarRight] : undefined}
    />
  );
}

export default PageHeader;
