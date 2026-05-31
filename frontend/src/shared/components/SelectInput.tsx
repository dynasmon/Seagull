import { Children, isValidElement, type OptionHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";
import { EuiSelect } from "@elastic/eui";
import type { EuiSelectOption } from "@elastic/eui";

interface SelectInputProps extends SelectHTMLAttributes<HTMLSelectElement> {
  error?: boolean;
  children: ReactNode;
}

function toOptions(children: ReactNode): EuiSelectOption[] {
  const options: EuiSelectOption[] = [];
  Children.forEach(children, (child) => {
    if (!isValidElement(child) || child.type !== "option") return;
    const { children: text, ...optionProps } = child.props as OptionHTMLAttributes<HTMLOptionElement> & { children?: ReactNode };
    options.push({ ...optionProps, text });
  });
  return options;
}

export function SelectInput({ error, className, children, value, ...rest }: SelectInputProps) {
  return (
    <EuiSelect
      compressed
      isInvalid={error}
      fullWidth
      className={className}
      value={value as string | number | undefined}
      options={toOptions(children)}
      {...rest}
    />
  );
}
