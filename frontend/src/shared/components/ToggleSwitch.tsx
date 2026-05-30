import { type ChangeEvent, type InputHTMLAttributes } from "react";
import { EuiSwitch } from "@elastic/eui";

interface ToggleSwitchProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: string;
}

export function ToggleSwitch({ label, id, checked, onChange, disabled, className }: ToggleSwitchProps) {
  return (
    <EuiSwitch
      compressed
      id={id}
      label={label ?? ""}
      showLabel={Boolean(label)}
      checked={Boolean(checked)}
      disabled={disabled}
      className={className}
      onChange={(event) => onChange?.(event as unknown as ChangeEvent<HTMLInputElement>)}
    />
  );
}
