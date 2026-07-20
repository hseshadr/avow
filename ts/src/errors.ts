/**
 * Coded envelope-error catalog — the TypeScript mirror of Python `avow.errors`.
 *
 * Every envelope failure carries a stable string `code` so callers (in any
 * language binding) branch on cause without string-matching messages. These are
 * the same codes the Python kernel raises, so a receipt that fails here fails
 * with the identical `code` it would fail with in CPython.
 */

/** Base class for every Avow envelope error. */
export class AvowError extends Error {
  public readonly code: string = "avow.error";

  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Payload could not be canonicalized to RFC 8785 JCS bytes. */
export class CanonicalizationFailed extends AvowError {
  public override readonly code = "avow.canonicalization_failed";
}

/** Ed25519 signature does not match the payload (or the pinned key). */
export class SignatureInvalid extends AvowError {
  public override readonly code = "avow.signature_invalid";
}

/** Recomputed content-hash does not match the receipt's stored hash. */
export class ReplayMismatch extends AvowError {
  public override readonly code = "avow.replay_mismatch";
}
