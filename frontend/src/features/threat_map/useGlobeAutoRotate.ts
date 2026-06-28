import { useEffect, useRef, type RefObject } from "react";
import type { GlobeMethods } from "react-globe.gl";

const AUTO_ROTATE_SPEED = 0.35;

export type GlobeAutoRotateOptions = {
  globeRef: RefObject<GlobeMethods | undefined>;
  containerRef: RefObject<HTMLDivElement>;
  ready: boolean;
  enabled: boolean;
  paused: boolean;
  onUserInteract: () => void;
};

export function useGlobeAutoRotate({
  globeRef,
  containerRef,
  ready,
  enabled,
  paused,
  onUserInteract,
}: GlobeAutoRotateOptions) {
  const interactRef = useRef(onUserInteract);
  interactRef.current = onUserInteract;

  useEffect(() => {
    if (!ready) return;
    const controls = globeRef.current?.controls();
    if (!controls) return;
    controls.autoRotateSpeed = AUTO_ROTATE_SPEED;
    controls.autoRotate = enabled && !paused;
  }, [ready, enabled, paused, globeRef]);

  useEffect(() => {
    if (!ready || !enabled) return;
    const node = containerRef.current;
    if (!node) return;
    const handlePointerDown = () => interactRef.current();
    node.addEventListener("pointerdown", handlePointerDown);
    return () => node.removeEventListener("pointerdown", handlePointerDown);
  }, [ready, enabled, containerRef]);
}
