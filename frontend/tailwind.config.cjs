/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "rgb(var(--background) / <alpha-value>)",
        foreground: "rgb(var(--foreground) / <alpha-value>)",
        card: "rgb(var(--card) / <alpha-value>)",
        muted: "rgb(var(--muted) / <alpha-value>)",
        "muted-foreground": "rgb(var(--muted-foreground) / <alpha-value>)",
        border: "rgb(var(--border) / <alpha-value>)",
        primary: "rgb(var(--primary) / <alpha-value>)",
        "primary-foreground": "rgb(var(--primary-foreground) / <alpha-value>)",
        "surface-1": "rgb(var(--surface-1) / <alpha-value>)",
        "surface-2": "rgb(var(--surface-2) / <alpha-value>)",
        "surface-3": "rgb(var(--surface-3) / <alpha-value>)",
        sidebar: "rgb(var(--sidebar) / <alpha-value>)",
        "sidebar-foreground": "rgb(var(--sidebar-foreground) / <alpha-value>)",
        "sidebar-muted": "rgb(var(--sidebar-muted) / <alpha-value>)",
        "sidebar-border": "rgb(var(--sidebar-border) / <alpha-value>)",
        "sidebar-accent": "rgb(var(--sidebar-accent) / <alpha-value>)",
        ring: "rgb(var(--ring) / <alpha-value>)",
        success: "rgb(var(--success) / <alpha-value>)",
        warning: "rgb(var(--warning) / <alpha-value>)",
        danger: "rgb(var(--danger) / <alpha-value>)",
        destructive: "rgb(var(--danger) / <alpha-value>)",
        info: "rgb(var(--info) / <alpha-value>)",
        "severity-critical": "rgb(var(--severity-critical) / <alpha-value>)",
        "severity-high": "rgb(var(--severity-high) / <alpha-value>)",
        "severity-medium": "rgb(var(--severity-medium) / <alpha-value>)",
        "severity-low": "rgb(var(--severity-low) / <alpha-value>)",
        "severity-neutral": "rgb(var(--severity-neutral) / <alpha-value>)"
      },
      borderRadius: {
        none: "0px",
        sm: "0.25rem",
        DEFAULT: "0.375rem",
        md: "0.5rem",
        lg: "0.625rem",
        xl: "0.75rem",
        "2xl": "1rem",
        full: "9999px"
      },
      boxShadow: {
        soft: "0 1px 2px rgb(2 8 20 / 0.04), 0 1px 3px rgb(2 8 20 / 0.06)",
        elevated: "0 1px 3px rgb(2 8 20 / 0.06), 0 8px 24px rgb(2 8 20 / 0.06)",
        pop: "0 12px 32px rgb(2 8 20 / 0.12), 0 4px 12px rgb(2 8 20 / 0.08)",
        drawer: "-12px 0 40px rgb(2 8 20 / 0.18)"
      },
      gridTemplateColumns: {
        24: "repeat(24, minmax(0, 1fr))"
      }
    }
  },
  plugins: []
};
