import type { TextareaHTMLAttributes } from "react";
import { EuiTextArea } from "@elastic/eui";

interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  error?: boolean;
}

export function TextArea({ error, className, ...rest }: TextAreaProps) {
  return <EuiTextArea compressed isInvalid={error} fullWidth className={className} {...rest} />;
}
