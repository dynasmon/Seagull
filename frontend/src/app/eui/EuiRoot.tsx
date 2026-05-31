import { useMemo } from "react";
import type { ReactNode } from "react";
import createCache from "@emotion/cache";
import { EuiProvider } from "@elastic/eui";
import { EuiThemeBorealis } from "@elastic/eui-theme-borealis";

type ColorMode = "light" | "dark";

function resolveInsertionPoint(): HTMLElement | undefined {
  if (typeof document === "undefined") return undefined;
  const el = document.querySelector('meta[name="emotion-insertion-point"]');
  return el instanceof HTMLElement ? el : undefined;
}

export default function EuiRoot({
  colorMode,
  children,
}: {
  colorMode: ColorMode;
  children: ReactNode;
}) {
  const cache = useMemo(() => {
    const insertionPoint = resolveInsertionPoint();
    return {
      default: createCache({ key: "eui", insertionPoint }),
      global: createCache({ key: "eui-global", insertionPoint }),
      utility: createCache({ key: "eui-utility", insertionPoint }),
    };
  }, []);

  return (
    <EuiProvider theme={EuiThemeBorealis} colorMode={colorMode} cache={cache}>
      {children}
    </EuiProvider>
  );
}
