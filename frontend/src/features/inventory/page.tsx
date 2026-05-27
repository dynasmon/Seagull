import { useInventoryPageModel } from "./hooks/useInventoryPageModel";
import { InventoryWorkspace } from "./components/InventoryWorkspace";

export default function InventoryPage() {
  const model = useInventoryPageModel();
  return <InventoryWorkspace model={model} />;
}
