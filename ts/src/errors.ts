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

/**
 * A receipt failed to verify under the pinned signer.
 *
 * The base of two security-distinct causes below. Catch this to mean "did not
 * verify, for any reason"; catch a subclass to distinguish *who signed it* from
 * *whether the bytes check out*.
 */
export class SignatureInvalid extends AvowError {
  public override readonly code: string = "avow.signature_invalid";
}

/**
 * The receipt's embedded key is not the signer the caller pinned.
 *
 * A PROVENANCE failure: someone signed this with a key you do not trust, so the
 * signature is never even checked. Coded distinctly so a caller can alert on
 * "wrong signer" without parsing a message.
 */
export class SignerMismatch extends SignatureInvalid {
  public override readonly code = "avow.signer_mismatch";
}

/**
 * The signer matched, but the Ed25519 check rejected the signature bytes.
 *
 * A TAMPER failure: the payload or the signature was altered. This is the case
 * `avow.signature_invalid` has always named, so it keeps that published code —
 * only the provenance case above gets a new one.
 */
export class SignatureBytesInvalid extends SignatureInvalid {}

/** Recomputed content-hash does not match the receipt's stored hash. */
export class ReplayMismatch extends AvowError {
  public override readonly code = "avow.replay_mismatch";
}
