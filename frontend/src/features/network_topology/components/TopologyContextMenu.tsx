type ContextMenuProps = {
  x: number;
  y: number;
  nodeLabel: string;
  nodeType: "device" | "group";
  onClose: () => void;
  onOpenDetail: () => void;
  onFocusGroup?: () => void;
  onIsolate: () => void;
  onCopyIp?: () => void;
};

export function TopologyContextMenu({
  x,
  y,
  nodeLabel,
  nodeType,
  onClose,
  onOpenDetail,
  onFocusGroup,
  onIsolate,
  onCopyIp,
}: ContextMenuProps) {
  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} />
      <div
        className="fixed z-50 min-w-[180px] rounded-lg border py-1 shadow-2xl"
        style={{
          left: x,
          top: y,
          background: "rgba(10,18,32,0.97)",
          borderColor: "rgba(148,163,184,0.15)",
          backdropFilter: "blur(12px)",
        }}
      >
        <div
          className="px-3 py-1.5 text-[11px] font-semibold"
          style={{ color: "rgba(148,163,184,0.5)" }}
        >
          {nodeLabel}
        </div>
        <hr style={{ borderColor: "rgba(148,163,184,0.08)" }} />
        <button
          className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-white/5"
          style={{ color: "rgba(226,232,240,0.85)" }}
          onClick={onOpenDetail}
        >
          <span>🔍</span> View details
        </button>
        {nodeType === "group" && onFocusGroup && (
          <button
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-white/5"
            style={{ color: "rgba(226,232,240,0.85)" }}
            onClick={onFocusGroup}
          >
            <span>◎</span> Focus this group
          </button>
        )}
        <button
          className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-white/5"
          style={{ color: "rgba(226,232,240,0.85)" }}
          onClick={onIsolate}
        >
          <span>⊙</span> Isolate in topology
        </button>
        {onCopyIp && (
          <button
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-white/5"
            style={{ color: "rgba(226,232,240,0.85)" }}
            onClick={onCopyIp}
          >
            <span>⎘</span> Copy IP
          </button>
        )}
      </div>
    </>
  );
}
