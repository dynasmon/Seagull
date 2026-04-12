export type UrlQueryUpdater<T> = T | ((prev: T) => T);

export function resolveNextUrlSearchParams<T>(
  prev: URLSearchParams,
  next: UrlQueryUpdater<T>,
  parse: (sp: URLSearchParams) => T,
  serialize: (state: T) => URLSearchParams
): URLSearchParams {
  const prevState = parse(prev);
  const resolved = typeof next === "function" ? (next as (current: T) => T)(prevState) : next;
  const nextSp = serialize(resolved);
  return nextSp.toString() === prev.toString() ? prev : nextSp;
}
