import EmptyState from "@/shared/components/EmptyState";

type Props = {
  title?: string;
  description?: string;
};

export function ExposureEmptyState({
  title = "No data",
  description = "No exposure data found.",
}: Props) {
  return <EmptyState title={title} description={description} />;
}
