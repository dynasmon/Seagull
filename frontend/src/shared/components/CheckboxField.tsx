import { useId, type InputHTMLAttributes, type ReactNode } from "react";
import { EuiCheckbox } from "@elastic/eui";

interface CheckboxFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label: ReactNode;
  helper?: ReactNode;
  error?: string | null;
}

export function CheckboxField({ label, helper, error, id, className, checked, onChange, disabled }: CheckboxFieldProps) {
  const generatedId = useId();

  return (
    <div className={className}>
      <EuiCheckbox id={id ?? generatedId} label={label} checked={checked} onChange={onChange ?? (() => undefined)} disabled={disabled} />
      {error ? (
        <p className="mt-1 text-[11px] text-danger" role="alert">
          {error}
        </p>
      ) : helper ? (
        <p className="mt-1 text-[11px] text-muted-foreground">{helper}</p>
      ) : null}
    </div>
  );
}
