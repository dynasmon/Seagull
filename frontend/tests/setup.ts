import { webcrypto } from "node:crypto";

// Node 18 does not expose globalThis.crypto, which @elastic/eui needs for id generation.
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}

// Component tests render to static markup without a DOM, but @elastic/eui popovers
// narrow their button prop with `instanceof HTMLElement` during render.
if (typeof (globalThis as { HTMLElement?: unknown }).HTMLElement === "undefined") {
  Object.defineProperty(globalThis, "HTMLElement", { value: class HTMLElement {}, configurable: true });
}
