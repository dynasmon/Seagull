import type { ReactNode } from "react";
import { createContext, useContext } from "react";

export type EventsHeaderApi = {
  /** Set the right-side toolbar region inside the Events header (layout). */
  setToolbarRight: (node: ReactNode | null) => void;
};

export const EventsHeaderContext = createContext<EventsHeaderApi | null>(null);

export function useEventsHeader(): EventsHeaderApi | null {
  return useContext(EventsHeaderContext);
}
