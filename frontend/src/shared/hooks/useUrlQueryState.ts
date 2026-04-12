import { useCallback, useEffect, useMemo, useRef } from "react";
import { useSearchParams } from "react-router-dom";

export type UrlQueryUpdater<T> = T | ((prev: T) => T);

export type UrlQueryStateOptions<T> = {
  parse: (sp: URLSearchParams) => T;
  serialize: (state: T) => URLSearchParams;
  replace?: boolean;
};

export function useUrlQueryState<T>({ parse, serialize, replace = true }: UrlQueryStateOptions<T>): [T, (next: UrlQueryUpdater<T>) => void, URLSearchParams] {
  const [searchParams, setSearchParams] = useSearchParams();
  const parseRef = useRef(parse);
  const serializeRef = useRef(serialize);

  useEffect(() => {
    parseRef.current = parse;
  }, [parse]);

  useEffect(() => {
    serializeRef.current = serialize;
  }, [serialize]);

  const state = useMemo(() => parse(searchParams), [parse, searchParams]);

  const setState = useCallback(
    (next: UrlQueryUpdater<T>) => {
      setSearchParams(
        (prev) => {
          const prevState = parseRef.current(prev);
          const resolved = typeof next === "function" ? (next as (current: T) => T)(prevState) : next;
          const nextSp = serializeRef.current(resolved);
          return nextSp.toString() === prev.toString() ? prev : nextSp;
        },
        { replace }
      );
    },
    [replace, setSearchParams]
  );

  return [state, setState, searchParams];
}

export default useUrlQueryState;
