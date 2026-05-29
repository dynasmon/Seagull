import { useState } from "react";
import {
  EuiButton,
  EuiButtonEmpty,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiForm,
  EuiFormRow,
  EuiPanel,
  EuiSearchBar,
  type Query,
  type SearchFilterConfig,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from "@elastic/eui";

const filters: SearchFilterConfig[] = [
  {
    type: "field_value_selection",
    field: "severity",
    name: "Severity",
    multiSelect: "or",
    options: [
      { value: "critical", view: "Critical" },
      { value: "high", view: "High" },
      { value: "medium", view: "Medium" },
      { value: "low", view: "Low" },
    ],
  },
  {
    type: "field_value_selection",
    field: "status",
    name: "Status",
    multiSelect: "or",
    options: [
      { value: "open", view: "Open" },
      { value: "acknowledged", view: "Acknowledged" },
      { value: "closed", view: "Closed" },
    ],
  },
];

export default function ToolbarDemo() {
  const [query, setQuery] = useState<Query | null>(null);

  return (
    <EuiPanel hasBorder paddingSize="l">
      <EuiTitle size="xs"><h3>Search + filter toolbar (EuiSearchBar)</h3></EuiTitle>
      <EuiSpacer size="s" />
      <EuiSearchBar
        box={{ placeholder: "Search alerts, hosts, rules…", incremental: true }}
        filters={filters}
        onChange={({ query: next }) => setQuery(next ?? null)}
      />
      <EuiSpacer size="s" />
      <EuiText size="xs" color="subdued"><p>Parsed query: <code>{query ? query.text || "(empty)" : "(empty)"}</code></p></EuiText>

      <EuiSpacer size="l" />
      <EuiTitle size="xs"><h3>Form rows (EuiForm)</h3></EuiTitle>
      <EuiSpacer size="s" />
      <EuiForm component="form">
        <EuiFlexGroup>
          <EuiFlexItem>
            <EuiFormRow label="Assignee">
              <EuiFieldText placeholder="analyst@org" />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiFormRow label="Disposition">
              <EuiSelect
                options={[
                  { value: "tp", text: "True positive" },
                  { value: "fp", text: "False positive" },
                  { value: "benign", text: "Benign" },
                ]}
              />
            </EuiFormRow>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="m" />
        <EuiFlexGroup justifyContent="flexEnd" gutterSize="s" responsive={false}>
          <EuiFlexItem grow={false}><EuiButtonEmpty>Cancel</EuiButtonEmpty></EuiFlexItem>
          <EuiFlexItem grow={false}><EuiButton fill>Save</EuiButton></EuiFlexItem>
        </EuiFlexGroup>
      </EuiForm>
    </EuiPanel>
  );
}
