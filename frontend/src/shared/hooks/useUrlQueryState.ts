import { useCallback, useEffect, useMemo, useRef } from "react";
import { useSearchParams } from "react-router-dom";

import { resolveNextUrlSearchParams, type UrlQueryUpdater } from "@/shared/lib/urlQueryState";
export type { UrlQueryUpdater };

export type UrlQueryStateOptions<T> = {
  parse: (sp: URLSearchParams) => T;
  serialize: (state: T) => URLSearchParams;
  replace?: boolean;
};

export function useUrlQueryState<T>({ parse, serialize, replace = true }: UrlQueryStateOptions<T>): [T, (next: UrlQueryUpdater<T>) => void, URLSearchParams] {
  const [searchParams, setSearchParams] = useSearchParams();
  const parseRef = useRef(parse);
  const serializeRef = useRef(serialize);
  const searchKey = searchParams.toString();

  useEffect(() => {
    parseRef.current = parse;
  }, [parse]);

  useEffect(() => {
    serializeRef.current = serialize;
  }, [serialize]);

  const state = useMemo(() => parse(searchParams), [parse, searchKey, searchParams]);

  const setState = useCallback(
    (next: UrlQueryUpdater<T>) => {
      setSearchParams(
        (prev) => resolveNextUrlSearchParams(prev, next, parseRef.current, serializeRef.current),
        { replace }
      );
    },
    [replace, setSearchParams]
  );

  return [state, setState, searchParams];
}

export default useUrlQueryState;
