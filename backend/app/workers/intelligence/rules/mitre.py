from typing import Any, Dict

from app.shared.taxonomy.catalog import technique_name


def _clamp_int(v: Any, lo: int, hi: int, default: int) -> int:
    try:
        n = int(v)
    except Exception:
        return int(default)
    return max(int(lo), min(int(hi), n))


def _extract_mitre_meta(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and normalize MITRE ATT&CK metadata from a rule dict.

    Expected schema in YAML:
        mitre:
          tactic: "discovery"
          technique_id: "T1046"
          technique: "Network Service Scanning"  # optional
          confidence: 75

    Returns an empty dict if no metadata is defined.
    """

    m = rule.get('mitre')
    if not isinstance(m, dict):
        return {}

    tactic = str(m.get('tactic') or '').strip() or None
    technique_id = str(m.get('technique_id') or m.get('technique') or '').strip() or None

    # If the YAML uses 'technique' as the name, keep it separate.
    technique = m.get('technique_name') if 'technique_name' in m else m.get('technique')
    technique = str(technique or '').strip() or None

    if technique_id and not technique:
        technique = technique_name(technique_id)

    confidence = _clamp_int(m.get('confidence', 50), 0, 100, 50)

    out: Dict[str, Any] = {}
    if tactic:
        out['tactic'] = tactic
    if technique_id:
        out['technique_id'] = technique_id
    if technique:
        out['technique'] = technique
    out['confidence'] = confidence

    return out
