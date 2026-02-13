/**
 * Cursor/keyset pagination envelope returned by the backend.
 *
 * - `items`: current page payload
 * - `next_cursor`: opaque cursor to fetch the next (older) page
 * - `has_more`: whether more pages exist
 */
export type CursorPage<T> = {
  items: T[];
  next_cursor: string | null;
  has_more: boolean;
};
