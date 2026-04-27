import { EvidenceRef } from "../types";

type Props = {
  refs: EvidenceRef[];
};

export function ExposureEvidenceList({ refs }: Props) {
  if (!refs.length) {
    return <p className="text-xs text-muted-foreground">No evidence references.</p>;
  }
  return (
    <ul className="space-y-2">
      {refs.map((ref, i) => (
        <li key={`${ref.source_type}:${ref.source_id}:${i}`} className="text-xs">
          <div className="font-medium">{ref.title || ref.source_id}</div>
          <div className="text-muted-foreground">{ref.source_type} · {ref.source_id}</div>
          {ref.summary && <div className="mt-0.5 text-muted-foreground">{ref.summary}</div>}
        </li>
      ))}
    </ul>
  );
}
