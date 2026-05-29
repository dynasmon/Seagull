import { useMemo, useState } from "react";
import {
  EuiBadge,
  EuiBasicTable,
  type EuiBasicTableColumn,
  type CriteriaWithPagination,
  EuiDataGrid,
  type EuiDataGridColumn,
  EuiHealth,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from "@elastic/eui";

import { useAgentsCatalog } from "@/app/providers";
import type { AgentPublic } from "@/features/agents/types";

function fmtDate(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

const gridColumns: EuiDataGridColumn[] = [
  { id: "agent_id", displayAsText: "Agent ID" },
  { id: "display_name", displayAsText: "Name" },
  { id: "tags", displayAsText: "Tags" },
  { id: "last_seen_at", displayAsText: "Last seen" },
  { id: "status", displayAsText: "Status" },
];

export default function TableDemo() {
  const { agents, isLoading } = useAgentsCatalog();

  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [sortField, setSortField] = useState<keyof AgentPublic>("agent_id");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("asc");
  const [visibleColumns, setVisibleColumns] = useState<string[]>(gridColumns.map((c) => c.id));

  const sorted = useMemo(() => {
    const copy = [...agents];
    copy.sort((a, b) => {
      const av = a[sortField];
      const bv = b[sortField];
      const as = av == null ? "" : String(av);
      const bs = bv == null ? "" : String(bv);
      return sortDirection === "asc" ? as.localeCompare(bs) : bs.localeCompare(as);
    });
    return copy;
  }, [agents, sortField, sortDirection]);

  const pageItems = useMemo(
    () => sorted.slice(pageIndex * pageSize, pageIndex * pageSize + pageSize),
    [sorted, pageIndex, pageSize],
  );

  const columns: Array<EuiBasicTableColumn<AgentPublic>> = [
    { field: "agent_id", name: "Agent ID", sortable: true, truncateText: true },
    { field: "display_name", name: "Name", sortable: true, render: (v: string | null | undefined) => v || "—" },
    {
      field: "tags",
      name: "Tags",
      render: (tags: string[]) =>
        tags && tags.length ? <>{tags.slice(0, 3).map((t) => <EuiBadge key={t} color="hollow">{t}</EuiBadge>)}</> : "—",
    },
    { field: "last_seen_at", name: "Last seen", sortable: true, render: (v: string | null | undefined) => fmtDate(v) },
    {
      field: "is_revoked",
      name: "Status",
      render: (v: boolean) => <EuiHealth color={v ? "danger" : "success"}>{v ? "Revoked" : "Active"}</EuiHealth>,
    },
  ];

  const onTableChange = ({ page, sort }: CriteriaWithPagination<AgentPublic>) => {
    if (page) {
      setPageIndex(page.index);
      setPageSize(page.size);
    }
    if (sort) {
      setSortField(sort.field);
      setSortDirection(sort.direction);
    }
  };

  return (
    <>
      <EuiPanel hasBorder paddingSize="l">
        <EuiTitle size="xs"><h3>Dense table (EuiBasicTable) — sortable, paginated · real agents data</h3></EuiTitle>
        <EuiText size="s" color="subdued">
          <p>{isLoading ? "Loading agents…" : `${agents.length} agents from the live catalog (no mock data).`}</p>
        </EuiText>
        <EuiSpacer size="s" />
        <EuiBasicTable<AgentPublic>
          items={pageItems}
          columns={columns}
          rowHeader="agent_id"
          itemId="agent_id"
          loading={isLoading}
          sorting={{ sort: { field: sortField, direction: sortDirection } }}
          pagination={{ pageIndex, pageSize, totalItemCount: sorted.length, pageSizeOptions: [10, 20, 50] }}
          onChange={onTableChange}
          noItemsMessage={isLoading ? "Loading…" : "No agents available"}
        />
      </EuiPanel>

      <EuiSpacer size="l" />

      <EuiPanel hasBorder paddingSize="l">
        <EuiTitle size="xs"><h3>Data grid (EuiDataGrid) — compact density</h3></EuiTitle>
        <EuiSpacer size="s" />
        <EuiDataGrid
          aria-label="Agents data grid"
          columns={gridColumns}
          columnVisibility={{ visibleColumns, setVisibleColumns }}
          rowCount={sorted.length}
          gridStyle={{ border: "horizontal", fontSize: "s", cellPadding: "s", stripes: true, rowHover: "highlight", header: "shade" }}
          renderCellValue={({ rowIndex, columnId }) => {
            const row = sorted[rowIndex];
            if (!row) return "";
            switch (columnId) {
              case "agent_id":
                return row.agent_id;
              case "display_name":
                return row.display_name || "—";
              case "tags":
                return (row.tags || []).join(", ") || "—";
              case "last_seen_at":
                return fmtDate(row.last_seen_at);
              case "status":
                return row.is_revoked ? "Revoked" : "Active";
              default:
                return "";
            }
          }}
        />
      </EuiPanel>
    </>
  );
}
