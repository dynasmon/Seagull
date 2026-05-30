import type { InputHTMLAttributes } from "react";
import { EuiFieldText } from "@elastic/eui";

interface TextInputProps extends InputHTMLAttributes<HTMLInputElement> {
  error?: boolean;
}

export function TextInput({ error, className, ...rest }: TextInputProps) {
  return <EuiFieldText compressed isInvalid={error} fullWidth className={className} {...rest} />;
}
