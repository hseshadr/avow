/** `@edgeproc/avow` — the portable TypeScript Avow trust kernel. */

export { canonicalBytes, contentHash, type JsonValue } from "./canonical.js";
export {
  AvowError,
  CanonicalizationFailed,
  PayloadHashMismatch,
  ReceiptSchemaMismatch,
  SignatureBytesInvalid,
  SignatureInvalid,
  SignerMismatch,
} from "./errors.js";
export { generateSeedHex, publicKeyHex } from "./keys.js";
export {
  RECEIPT_SCHEMA,
  type SignedReceipt,
  signPayload,
  verifySignature,
} from "./receipt.js";
