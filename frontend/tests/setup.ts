import { webcrypto } from "node:crypto";

// Node 18 does not expose globalThis.crypto, which @elastic/eui needs for id generation.
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}
