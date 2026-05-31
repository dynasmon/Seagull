import { type ButtonHTMLAttributes, type ReactNode } from "react";
import { EuiButton, EuiButtonEmpty } from "@elastic/eui";

import { cx } from "@/shared/lib/cx";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "success" | "subtle";
export type ButtonSize = "sm" | "md" | "lg" | "icon";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  children?: ReactNode;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
}

function euiSize(size: ButtonSize): "s" | "m" {
  return size === "lg" ? "m" : "s";
}

function euiColor(variant: ButtonVariant): "primary" | "danger" | "success" | "text" {
  if (variant === "danger") return "danger";
  if (variant === "success") return "success";
  if (variant === "primary") return "primary";
  return "text";
}

function ButtonContent({
  children,
  leadingIcon,
  trailingIcon,
}: {
  children?: ReactNode;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
}) {
  return (
    <>
      {leadingIcon ? <span className="inline-flex shrink-0">{leadingIcon}</span> : null}
      {children}
      {trailingIcon ? <span className="inline-flex shrink-0">{trailingIcon}</span> : null}
    </>
  );
}

export function Button({
  variant = "secondary",
  size = "md",
  disabled,
  className,
  children,
  leadingIcon,
  trailingIcon,
  ...rest
}: ButtonProps) {
  const color = euiColor(variant);
  const buttonType = rest.type ?? "button";
  const buttonAttrs = rest as Omit<ButtonHTMLAttributes<HTMLButtonElement>, "color" | "disabled" | "type" | "value">;

  if (size === "icon") {
    const iconContent = leadingIcon ?? children ?? trailingIcon;
    const squareClassName = cx("w-8 shrink-0 justify-center", className);
    if (variant === "ghost") {
      return (
        <EuiButtonEmpty
          {...buttonAttrs}
          color={color}
          size="s"
          type={buttonType}
          isDisabled={disabled}
          className={squareClassName}
          contentProps={{ className: "px-0" }}
        >
          {iconContent}
        </EuiButtonEmpty>
      );
    }
    return (
      <EuiButton
        {...buttonAttrs}
        fill={variant === "primary"}
        color={color}
        size="s"
        minWidth={0}
        type={buttonType}
        isDisabled={disabled}
        className={squareClassName}
        contentProps={{ className: "px-0" }}
      >
        {iconContent}
      </EuiButton>
    );
  }

  const content = <ButtonContent leadingIcon={leadingIcon} trailingIcon={trailingIcon}>{children}</ButtonContent>;

  if (variant === "ghost") {
    return (
      <EuiButtonEmpty
        {...buttonAttrs}
        color={color}
        size={euiSize(size)}
        type={buttonType}
        isDisabled={disabled}
        className={className}
      >
        {content}
      </EuiButtonEmpty>
    );
  }

  return (
    <EuiButton
      {...buttonAttrs}
      fill={variant === "primary"}
      color={color}
      size={euiSize(size)}
      type={buttonType}
      isDisabled={disabled}
      className={className}
    >
      {content}
    </EuiButton>
  );
}
