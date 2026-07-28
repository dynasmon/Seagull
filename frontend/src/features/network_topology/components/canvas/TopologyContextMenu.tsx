import { useEffect, useRef, useState } from "react";

const MENU_W = 210;

export type TopologyContextAction = {
  key: string;
  label: string;
  hint?: string;
  href?: string;
  onSelect?: () => void;
};

type ContextMenuProps = {
  x: number;
  y: number;
  title: string;
  subtitle?: string | null;
  actions: TopologyContextAction[];
  onClose: () => void;
};

export function TopologyContextMenu({ x, y, title, subtitle, actions, onClose }: ContextMenuProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState({ left: x, top: y });

  useEffect(() => {
    const height = ref.current?.offsetHeight ?? 0;
    const maxLeft = window.innerWidth - MENU_W - 8;
    const maxTop = window.innerHeight - height - 8;
    setPosition({ left: Math.max(8, Math.min(x, maxLeft)), top: Math.max(8, Math.min(y, maxTop)) });
  }, [x, y, actions.length]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} onContextMenu={(e) => { e.preventDefault(); onClose(); }} />
      <div
        ref={ref}
        role="menu"
        className="fixed z-50 rounded-lg border py-1 shadow-2xl"
        style={{
          left: position.left,
          top: position.top,
          width: MENU_W,
          background: "rgba(10,18,32,0.98)",
          borderColor: "rgba(148,163,184,0.18)",
          backdropFilter: "blur(12px)",
        }}
      >
        <div className="px-3 pb-1.5 pt-1">
          <div className="truncate text-[11px] font-semibold" style={{ color: "rgba(226,232,240,0.9)" }} title={title}>
            {title}
          </div>
          {subtitle && (
            <div className="truncate text-[10px]" style={{ color: "rgba(148,163,184,0.6)" }}>
              {subtitle}
            </div>
          )}
        </div>
        <hr style={{ borderColor: "rgba(148,163,184,0.1)" }} />
        {actions.map((action) =>
          action.href ? (
            <a
              key={action.key}
              role="menuitem"
              href={action.href}
              className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-xs hover:bg-white/5"
              style={{ color: "rgba(226,232,240,0.85)" }}
              onClick={onClose}
            >
              <span>{action.label}</span>
              {action.hint && <span style={{ color: "rgba(148,163,184,0.5)" }}>{action.hint}</span>}
            </a>
          ) : (
            <button
              key={action.key}
              type="button"
              role="menuitem"
              className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-xs hover:bg-white/5"
              style={{ color: "rgba(226,232,240,0.85)" }}
              onClick={() => {
                action.onSelect?.();
                onClose();
              }}
            >
              <span>{action.label}</span>
              {action.hint && <span style={{ color: "rgba(148,163,184,0.5)" }}>{action.hint}</span>}
            </button>
          ),
        )}
      </div>
    </>
  );
}
