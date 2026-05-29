import { useState } from "react";
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from "@elastic/eui";

export default function FlyoutDemo() {
  const [open, setOpen] = useState(false);

  return (
    <EuiPanel hasBorder paddingSize="l">
      <EuiTitle size="xs"><h3>Flyout (EuiFlyout) — Drawer contract parity</h3></EuiTitle>
      <EuiText size="s" color="subdued">
        <p>Validates focus trap, Esc-to-close, overlay mask, sizing, and header/body/footer regions — all native to EuiFlyout.</p>
      </EuiText>
      <EuiSpacer size="s" />
      <EuiButton size="s" iconType="inspect" onClick={() => setOpen(true)}>Open evidence flyout</EuiButton>

      {open ? (
        <EuiFlyout onClose={() => setOpen(false)} size="m" type="overlay" aria-labelledby="lab-flyout-title">
          <EuiFlyoutHeader hasBorder>
            <EuiText size="xs" color="subdued"><p>EVIDENCE</p></EuiText>
            <EuiTitle size="s"><h2 id="lab-flyout-title">Alert evidence — sample</h2></EuiTitle>
          </EuiFlyoutHeader>
          <EuiFlyoutBody>
            <EuiCallOut size="s" title="Native accessibility" iconType="check" color="success">
              Esc closes the flyout, focus is trapped, and the overlay mask is managed by EUI.
            </EuiCallOut>
            <EuiSpacer size="s" />
            <EuiText size="s"><p>The body region scrolls independently. This mirrors our current Drawer body region and contract.</p></EuiText>
          </EuiFlyoutBody>
          <EuiFlyoutFooter>
            <EuiFlexGroup justifyContent="spaceBetween" responsive={false}>
              <EuiFlexItem grow={false}><EuiButtonEmpty onClick={() => setOpen(false)}>Close</EuiButtonEmpty></EuiFlexItem>
              <EuiFlexItem grow={false}><EuiButton fill onClick={() => setOpen(false)}>Add to investigation</EuiButton></EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlyoutFooter>
        </EuiFlyout>
      ) : null}
    </EuiPanel>
  );
}
