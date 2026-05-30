import { useMemo } from "react";
import { EuiFacetButton, EuiFacetGroup } from "@elastic/eui";

type Row = { key: string; count: number };

type NewTypeRow = { key?: string; type?: string; count: number };

type Props = {
  title?: string;

  rows?: Row[];
  selectedKey?: string | null;
  onSelect?: (key: string) => void;

  activeType?: string | null;
  types?: NewTypeRow[];
  onSelectType?: (t: string) => void;
  onClearType?: () => void;
};

function normalizeRowsFromTypes(types: NewTypeRow[] | undefined | null): Row[] {
  const list = (types ?? []).map((t) => ({
    key: (t.key ?? t.type ?? "").trim(),
    count: Number.isFinite(Number((t as any).count)) ? Number((t as any).count) : 0,
  }));
  return list.filter((r) => r.key);
}

export default function EventExplorer(props: Props) {
  const { rows, selectedKey, onSelect, activeType, types, onSelectType, onClearType } = props;

  const isNew =
    typeof onSelectType === "function" ||
    typeof onClearType === "function" ||
    Array.isArray(types) ||
    activeType !== undefined;

  const effectiveRows: Row[] = useMemo(() => {
    return isNew ? normalizeRowsFromTypes(types) : (rows ?? []);
  }, [isNew, types, rows]);

  const items = useMemo(() => {
    const total = (effectiveRows ?? []).reduce((acc, r) => acc + (r.count || 0), 0);
    const base: Row[] = [{ key: "", count: total }, ...(effectiveRows ?? [])];
    return base;
  }, [effectiveRows]);

  const effectiveSelectedKey = (isNew ? (activeType ?? "") : (selectedKey ?? "")) || "";

  function handleSelect(key: string) {
    const k = (key ?? "").trim();

    if (isNew) {
      if (!k) {
        onClearType?.();
        if (!onClearType) onSelectType?.("");
        return;
      }
      onSelectType?.(k);
      return;
    }

    onSelect?.(k);
  }

  return (
    <EuiFacetGroup layout="vertical" gutterSize="none">
      {items.map((r) => {
        const active = effectiveSelectedKey === (r.key || "");
        const label = r.key ? r.key : "All events";
        return (
          <EuiFacetButton
            key={r.key || "__all__"}
            quantity={r.count}
            isSelected={active}
            onClick={() => handleSelect(r.key)}
          >
            <span className="font-mono text-[12px]">{label}</span>
          </EuiFacetButton>
        );
      })}
    </EuiFacetGroup>
  );
}
