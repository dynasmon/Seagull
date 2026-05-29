import { type ButtonHTMLAttributes, type ComponentType, type ReactNode, type SVGProps } from "react";
import { EuiButton, EuiButtonEmpty, EuiButtonIcon } from "@elastic/eui";
import type { IconType } from "@elastic/eui";

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

function contentIconType(icon: ReactNode): IconType {
  const Icon: ComponentType<SVGProps<SVGSVGElement>> = (props) => (
    <svg {...props} viewBox="0 0 16 16">
      <foreignObject x="0" y="0" width="16" height="16">
        <span className="flex h-4 w-4 items-center justify-center text-current">{icon}</span>
      </foreignObject>
    </svg>
  );
  return Icon;
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
    const iconNode = leadingIcon ?? children ?? trailingIcon;
    return (
      <EuiButtonIcon
        {...buttonAttrs}
        iconType={iconNode ? contentIconType(iconNode) : "empty"}
        display={variant === "primary" ? "fill" : variant === "ghost" ? "empty" : "base"}
        color={color}
        size="s"
        type={buttonType}
        isDisabled={disabled}
        className={cx("shrink-0", className)}
      />
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
