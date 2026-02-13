/**
 * Minimal className joiner.
 * Keeps the project dependency-free for class composition.
 */
export function cx(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}
