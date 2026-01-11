/**
 * ============================================================================
 * VERIFIABLE CREDENTIALS v2.0 VERIFIER
 * ============================================================================
 *
 * This module implements credential verification following the W3C Verifiable
 * Credentials Data Model 2.0 specification.
 *
 * @see https://www.w3.org/TR/vc-data-model-2.0/
 *
 * ============================================================================
 * THE VERIFICATION PROCESS
 * ============================================================================
 *
 * Verification is the reverse of signing. A verifier receives a credential
 * and checks that:
 * 1. The signature is mathematically valid
 * 2. The credential hasn't been tampered with
 * 3. The issuer actually signed it (using their public key)
 *
 * This does NOT verify:
 * - That the issuer is trustworthy (that's a policy decision)
 * - That the claims are true (only that the issuer made them)
 * - That the credential hasn't been revoked (requires a revocation check)
 *
 * ============================================================================
 */

import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

// Required: Configure ed25519 to use sha512 for hashing
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

/**
 * ============================================================================
 * HELPER: JSON CANONICALIZATION SCHEME (JCS)
 * ============================================================================
 *
 * Same canonicalization used during signing. The verifier must produce
 * the exact same canonical form to verify the signature.
 *
 * @param {any} obj - The object to canonicalize
 * @returns {string} - Canonicalized JSON string
 */
function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    const elements = obj.map(item => canonicalize(item));
    return '[' + elements.join(',') + ']';
  }

  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(key => {
    const canonicalValue = canonicalize(obj[key]);
    return JSON.stringify(key) + ':' + canonicalValue;
  });

  return '{' + pairs.join(',') + '}';
}

/**
 * ============================================================================
 * HELPER: BASE64URL DECODING
 * ============================================================================
 *
 * Decodes Base64URL encoded strings back to bytes.
 * This is the reverse of the encoding done during signing.
 *
 * Base64URL differences from Base64:
 * 1. '-' instead of '+'
 * 2. '_' instead of '/'
 * 3. No padding '=' characters
 *
 * @param {string} str - Base64URL encoded string
 * @returns {Uint8Array} - Decoded bytes
 */
function base64urlDecode(str) {
  // Convert base64url to base64: replace - with +, _ with /
  let base64 = str
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  // Add padding if needed (base64 strings must be multiple of 4)
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  // Decode base64 to bytes
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes;
}

/**
 * ============================================================================
 * MAIN FUNCTION: VERIFY A VERIFIABLE CREDENTIAL
 * ============================================================================
 *
 * This function verifies the cryptographic integrity of a Verifiable Credential.
 *
 * THE VERIFICATION PROCESS (4 Steps):
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 1: EXTRACT AND VALIDATE THE PROOF                                  │
 * │ Check that the credential has a proof object with required fields.      │
 * │ Extract the signature from proofValue.                                  │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 2: RECONSTRUCT THE UNSIGNED CREDENTIAL                             │
 * │ Remove the proof object to get the original unsigned credential.        │
 * │ This is what was signed during issuance.                                │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 3: CANONICALIZE AND HASH                                           │
 * │ Apply the same JCS canonicalization and SHA-256 hashing                 │
 * │ that was used during signing.                                           │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 4: VERIFY THE SIGNATURE                                            │
 * │ Use Ed25519 to verify the signature against the hash                    │
 * │ using the issuer's public key.                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @param {Object} credential - The Verifiable Credential to verify
 * @param {Uint8Array} publicKey - The issuer's Ed25519 public key
 * @returns {Promise<Object>} Verification result with validity and details
 */
export async function verifyCredential(credential, publicKey) {
  const result = {
    verified: false,
    checks: {
      hasProof: false,
      proofType: false,
      cryptosuite: false,
      signatureValid: false
    },
    errors: []
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 1: EXTRACT AND VALIDATE THE PROOF
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // The proof object contains:
  // - type: Should be "DataIntegrityProof" for VC 2.0
  // - cryptosuite: Should be "eddsa-jcs-2022" for Ed25519 + JCS
  // - proofValue: The actual signature (base64url encoded with 'z' prefix)
  //
  // We validate these fields before attempting signature verification.

  if (!credential.proof) {
    result.errors.push('Credential has no proof object');
    return result;
  }
  result.checks.hasProof = true;

  const proof = credential.proof;

  if (proof.type !== 'DataIntegrityProof') {
    result.errors.push(`Unsupported proof type: ${proof.type}. Expected: DataIntegrityProof`);
    return result;
  }
  result.checks.proofType = true;

  if (proof.cryptosuite !== 'eddsa-jcs-2022') {
    result.errors.push(`Unsupported cryptosuite: ${proof.cryptosuite}. Expected: eddsa-jcs-2022`);
    return result;
  }
  result.checks.cryptosuite = true;

  // Extract the signature from proofValue
  // The 'z' prefix indicates base64url encoding (multibase standard)
  const proofValue = proof.proofValue;
  if (!proofValue || !proofValue.startsWith('z')) {
    result.errors.push('Invalid proofValue: must start with "z" (multibase base64url prefix)');
    return result;
  }

  // Remove the 'z' prefix and decode the signature
  const signatureBase64url = proofValue.slice(1);
  let signature;
  try {
    signature = base64urlDecode(signatureBase64url);
  } catch (e) {
    result.errors.push(`Failed to decode signature: ${e.message}`);
    return result;
  }

  // Ed25519 signatures should be 64 bytes
  if (signature.length !== 64) {
    result.errors.push(`Invalid signature length: ${signature.length} bytes. Expected: 64 bytes`);
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 2: RECONSTRUCT THE UNSIGNED CREDENTIAL
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // During signing, the issuer signed the credential WITHOUT the proof.
  // To verify, we must reconstruct that exact same unsigned credential.
  //
  // We create a copy without the proof object.

  const unsignedCredential = { ...credential };
  delete unsignedCredential.proof;

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 3: CANONICALIZE AND HASH
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // Apply the same transformation as during signing:
  // 1. Canonicalize with JCS (ensures consistent byte order)
  // 2. Hash with SHA-256 (creates the fingerprint)
  //
  // If the credential was modified in any way, the hash will be different
  // and the signature will not verify.

  const canonicalCredential = canonicalize(unsignedCredential);
  const credentialBytes = new TextEncoder().encode(canonicalCredential);
  const hash = sha256(credentialBytes);

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 4: VERIFY THE SIGNATURE
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // Ed25519 verification takes:
  // - The signature (from the proof)
  // - The hash (what should have been signed)
  // - The public key (to verify who signed it)
  //
  // If verification succeeds, we know:
  // 1. The credential hasn't been tampered with (hash matches)
  // 2. It was signed by someone with the corresponding private key

  try {
    const isValid = await ed25519.verifyAsync(signature, hash, publicKey);
    result.checks.signatureValid = isValid;

    if (isValid) {
      result.verified = true;
    } else {
      result.errors.push('Signature verification failed: signature does not match credential');
    }
  } catch (e) {
    result.errors.push(`Signature verification error: ${e.message}`);
  }

  return result;
}

/**
 * ============================================================================
 * UTILITY: DECODE PUBLIC KEY FROM MULTIBASE FORMAT
 * ============================================================================
 *
 * Decodes a public key from the multibase format used in DID documents.
 * The format is "z6Mk" + base64url encoded public key.
 *
 * @param {string} publicKeyMultibase - The multibase-encoded public key
 * @returns {Uint8Array} The raw Ed25519 public key bytes
 */
export function decodePublicKey(publicKeyMultibase) {
  // Check for the "z6Mk" prefix (z = base64url, 6Mk = Ed25519 multicodec)
  if (!publicKeyMultibase.startsWith('z6Mk')) {
    throw new Error('Invalid public key format: expected "z6Mk" prefix for Ed25519');
  }

  // Remove the "z6Mk" prefix and decode
  const keyBase64url = publicKeyMultibase.slice(4);
  return base64urlDecode(keyBase64url);
}
