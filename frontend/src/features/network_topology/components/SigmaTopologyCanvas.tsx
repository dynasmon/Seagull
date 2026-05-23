import {
  Component,
  lazy,
  Suspense,
  type ComponentProps,
  type ReactNode,
} from "react";

import TopologyCanvas from "./TopologyCanvas";

type Props = ComponentProps<typeof TopologyCanvas>;

const LazySigmaTopologyCanvas = lazy(async () => {
  try {
    return await import("./SigmaTopologyCanvasImpl");
  } catch (error) {
    console.warn(
      "Falling back to ReactFlow topology canvas after sigma failed to load.",
      error,
    );
    return { default: TopologyCanvas };
  }
});

function canAttemptSigma(): boolean {
  if (typeof window === "undefined") return false;
  const urlApi =
    window.URL ?? (window as Window & { webkitURL?: typeof URL }).webkitURL;
  return Boolean(
    window.WebGL2RenderingContext &&
    window.Worker &&
    window.Blob &&
    urlApi?.createObjectURL,
  );
}

class SigmaCanvasErrorBoundary extends Component<
  { canvasProps: Props; children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error: Error): void {
    console.warn(
      "Falling back to ReactFlow topology canvas after sigma failed to render.",
      error,
    );
  }

  render() {
    if (this.state.failed) {
      return <TopologyCanvas {...this.props.canvasProps} />;
    }
    return this.props.children;
  }
}

export default function SigmaTopologyCanvas(props: Props) {
  if (!canAttemptSigma()) {
    return <TopologyCanvas {...props} />;
  }

  return (
    <SigmaCanvasErrorBoundary canvasProps={props}>
      <Suspense fallback={<TopologyCanvas {...props} />}>
        <LazySigmaTopologyCanvas {...props} />
      </Suspense>
    </SigmaCanvasErrorBoundary>
  );
}
