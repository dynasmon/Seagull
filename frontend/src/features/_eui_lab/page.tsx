import { EuiCallOut, EuiSpacer, EuiTabbedContent, type EuiTabbedContentTab } from "@elastic/eui";

import ShellDemo from "./sections/ShellDemo";
import FlyoutDemo from "./sections/FlyoutDemo";
import TableDemo from "./sections/TableDemo";
import ToolbarDemo from "./sections/ToolbarDemo";
import PrimitivesDemo from "./sections/PrimitivesDemo";

const tabs: EuiTabbedContentTab[] = [
  { id: "shell", name: "Shell", content: <><EuiSpacer /><ShellDemo /></> },
  { id: "flyout", name: "Flyout", content: <><EuiSpacer /><FlyoutDemo /></> },
  { id: "tables", name: "Tables & grid", content: <><EuiSpacer /><TableDemo /></> },
  { id: "toolbar", name: "Search & forms", content: <><EuiSpacer /><ToolbarDemo /></> },
  { id: "primitives", name: "Primitives", content: <><EuiSpacer /><PrimitivesDemo /></> },
];

export default function EuiLabPage() {
  return (
    <div className="space-y-4 pb-16">
      <EuiCallOut title="EUI compatibility spike" iconType="beaker" color="primary" size="s">
        Isolated, disposable lab route validating @elastic/eui (Borealis) inside the existing Tailwind shell. Not linked in navigation.
      </EuiCallOut>
      <EuiTabbedContent tabs={tabs} initialSelectedTab={tabs[0]} autoFocus="selected" />
    </div>
  );
}
