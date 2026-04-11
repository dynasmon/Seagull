import EventsStreamPage from "@/features/events/views/stream/page";

export default function DdosEventsPage() {
  return <EventsStreamPage forcedEventType="dos_attack" moduleTitle="DDoS Event Stream" />;
}
