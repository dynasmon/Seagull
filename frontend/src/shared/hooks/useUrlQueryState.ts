import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

export type UrlQueryUpdater<T> = T | ((prev: T) => T);

export type UrlQueryStateOptions<T> = {
  parse: (sp: URLSearchParams) => T;
  serialize: (state: T) => URLSearchParams;
  replace?: boolean;
};

export function useUrlQueryState<T>({ parse, serialize, replace = true }: UrlQueryStateOptions<T>): [T, (next: UrlQueryUpdater<T>) => void, URLSearchParams] {
  const [searchParams, setSearchParams] = useSearchParams();

  const state = useMemo(() => parse(searchParams), [parse, searchParams]);

  const setState = useCallback(
    (next: UrlQueryUpdater<T>) => {
      setSearchParams(
        (prev) => {
          const prevState = parse(prev);
          const resolved = typeof next === "function" ? (next as (current: T) => T)(prevState) : next;
          const nextSp = serialize(resolved);
          return nextSp.toString() === prev.toString() ? prev : nextSp;
        },
        { replace }
      );
    },
    [parse, replace, serialize, setSearchParams]
  );

  return [state, setState, searchParams];
}

export default useUrlQueryState;
