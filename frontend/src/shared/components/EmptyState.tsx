export default function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="border border-border/60 bg-card/10 p-4">
      <div className="text-xs font-mono font-bold uppercase tracking-widest text-primary/90">{title}</div>
      {hint && <div className="mt-2 text-sm text-muted-foreground">{hint}</div>}
    </div>
  );
}
