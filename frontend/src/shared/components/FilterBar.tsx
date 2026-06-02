import { useState, type ReactNode } from "react";
import {
  EuiFilterGroup,
  EuiFilterButton,
  EuiPopover,
  EuiSelectable,
} from "@elastic/eui";
import type { EuiSelectableOption } from "@elastic/eui";

export interface FilterOption {
  value: string;
  label?: string;
  count?: number;
}

export function FilterBar({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <EuiFilterGroup compressed className={className}>
      {children}
    </EuiFilterGroup>
  );
}

function CountAppend({ count }: { count: number }) {
  return <span className="font-mono text-[11px] text-muted-foreground">{count}</span>;
}

function optionListHeight(count: number, searchable: boolean): number {
  const rows = Math.min(Math.max(count, 1), 8);
  return rows * 32 + (searchable ? 4 : 0);
}

export function FilterButtonSelect({
  label,
  value,
  options,
  onChange,
  searchable = false,
  panelWidth = 240,
}: {
  label: string;
  value: string;
  options: FilterOption[];
  onChange: (next: string) => void;
  searchable?: boolean;
  panelWidth?: number;
}) {
  const [open, setOpen] = useState(false);

  const defaultValue = options[0]?.value;
  const active = value !== defaultValue;
  const selectedLabel = options.find((o) => o.value === value)?.label ?? value;

  const euiOptions: EuiSelectableOption[] = options.map((o) => ({
    label: o.label ?? o.value,
    key: o.value,
    checked: o.value === value ? "on" : undefined,
    append: o.count !== undefined ? <CountAppend count={o.count} /> : undefined,
  }));

  const button = (
    <EuiFilterButton
      iconType="arrowDown"
      onClick={() => setOpen((v) => !v)}
      isSelected={open}
      hasActiveFilters={active}
      grow={false}
    >
      {active ? `${label}: ${selectedLabel}` : label}
    </EuiFilterButton>
  );

  return (
    <EuiPopover
      button={button}
      isOpen={open}
      closePopover={() => setOpen(false)}
      panelPaddingSize="none"
      anchorPosition="downLeft"
    >
      <div style={{ width: panelWidth }}>
        <EuiSelectable
          aria-label={label}
          searchable={searchable}
          options={euiOptions}
          singleSelection="always"
          height={optionListHeight(options.length, searchable)}
          onChange={(next) => {
            const chosen = next.find((o) => o.checked === "on");
            onChange(chosen ? String(chosen.key) : defaultValue);
            setOpen(false);
          }}
        >
          {(list, search) => (
            <>
              {searchable ? <div className="border-b border-border/60 p-2">{search}</div> : null}
              {list}
            </>
          )}
        </EuiSelectable>
      </div>
    </EuiPopover>
  );
}

export function FilterButtonMultiSelect({
  label,
  selected,
  options,
  onChange,
  searchable = false,
  panelWidth = 240,
}: {
  label: string;
  selected: string[];
  options: FilterOption[];
  onChange: (next: string[]) => void;
  searchable?: boolean;
  panelWidth?: number;
}) {
  const [open, setOpen] = useState(false);
  const numActive = selected.length;

  const euiOptions: EuiSelectableOption[] = options.map((o) => ({
    label: o.label ?? o.value,
    key: o.value,
    checked: selected.includes(o.value) ? "on" : undefined,
    append: o.count !== undefined ? <CountAppend count={o.count} /> : undefined,
  }));

  const button = (
    <EuiFilterButton
      iconType="arrowDown"
      onClick={() => setOpen((v) => !v)}
      isSelected={open}
      hasActiveFilters={numActive > 0}
      numActiveFilters={numActive > 0 ? numActive : undefined}
      numFilters={options.length}
      grow={false}
    >
      {label}
    </EuiFilterButton>
  );

  return (
    <EuiPopover
      button={button}
      isOpen={open}
      closePopover={() => setOpen(false)}
      panelPaddingSize="none"
      anchorPosition="downLeft"
    >
      <div style={{ width: panelWidth }}>
        <EuiSelectable
          aria-label={label}
          searchable={searchable}
          options={euiOptions}
          height={optionListHeight(options.length, searchable)}
          onChange={(next) =>
            onChange(next.filter((o) => o.checked === "on").map((o) => String(o.key)))
          }
        >
          {(list, search) => (
            <>
              {searchable ? <div className="border-b border-border/60 p-2">{search}</div> : null}
              {list}
            </>
          )}
        </EuiSelectable>
      </div>
    </EuiPopover>
  );
}
