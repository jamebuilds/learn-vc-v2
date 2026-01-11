/**
 * ============================================================================
 * VERIFIABLE CREDENTIALS v2.0 ISSUER
 * ============================================================================
 *
 * This module implements credential issuance following the W3C Verifiable
 * Credentials Data Model 2.0 specification.
 *
 * @see https://www.w3.org/TR/vc-data-model-2.0/
 *
 * ============================================================================
 * WHAT IS A VERIFIABLE CREDENTIAL?
 * ============================================================================
 *
 * A Verifiable Credential (VC) is a tamper-evident credential that has authorship
 * that can be cryptographically verified. Think of it as a digital version of
 * physical credentials like:
 *   - Driver's licenses
 *   - University degrees
 *   - Employee badges
 *   - Vaccination records
 *
 * The key difference is that VCs can be verified instantly by anyone, without
 * needing to contact the issuer.
 *
 * ============================================================================
 * THE THREE ROLES IN THE VC ECOSYSTEM
 * ============================================================================
 *
 *   ┌─────────┐     issues      ┌────────────┐     presents to     ┌──────────┐
 *   │ ISSUER  │ ──────────────> │   HOLDER   │ ─────────────────> │ VERIFIER │
 *   └─────────┘                 └────────────┘                     └──────────┘
 *
 * 1. ISSUER: Creates and signs credentials (e.g., a university issuing degrees)
 * 2. HOLDER: Receives and stores credentials (e.g., a student with their diploma)
 * 3. VERIFIER: Checks credential validity (e.g., an employer verifying a degree)
 *
 * ============================================================================
 */

import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

// Required: Configure ed25519 to use sha512 for hashing
// Ed25519 internally uses SHA-512 for signature generation
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

/**
 * ============================================================================
 * HELPER: JSON CANONICALIZATION SCHEME (JCS)
 * ============================================================================
 *
 * Before signing a credential, we need to convert it to a canonical (standard)
 * form. This ensures that the same credential always produces the same bytes,
 * regardless of how the JSON was originally formatted.
 *
 * JCS (RFC 8785) defines rules for canonical JSON:
 * 1. Object keys must be sorted alphabetically (Unicode order)
 * 2. No whitespace between elements
 * 3. Numbers in specific format
 *
 * Without canonicalization:
 *   {"b": 1, "a": 2}  →  different bytes than  →  {"a": 2, "b": 1}
 *
 * With canonicalization:
 *   Both become: {"a":2,"b":1}  →  same bytes  →  same signature
 *
 * @param {any} obj - The object to canonicalize
 * @returns {string} - Canonicalized JSON string
 */
function canonicalize(obj) {
  // Handle primitive types directly
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  // Handle arrays: canonicalize each element, preserve order
  if (Array.isArray(obj)) {
    const elements = obj.map(item => canonicalize(item));
    return '[' + elements.join(',') + ']';
  }

  // Handle objects: sort keys alphabetically, then canonicalize values
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(key => {
    const canonicalValue = canonicalize(obj[key]);
    return JSON.stringify(key) + ':' + canonicalValue;
  });

  return '{' + pairs.join(',') + '}';
}

/**
 * ============================================================================
 * HELPER: BASE64URL ENCODING
 * ============================================================================
 *
 * Verifiable Credentials use Base64URL encoding (not regular Base64) for
 * signatures. Base64URL is URL-safe because it:
 * 1. Uses '-' instead of '+'
 * 2. Uses '_' instead of '/'
 * 3. Omits padding '=' characters
 *
 * This makes credentials safe to include in URLs and JSON without escaping.
 *
 * @param {Uint8Array} bytes - Raw bytes to encode
 * @returns {string} - Base64URL encoded string
 */
function base64urlEncode(bytes) {
  // Convert bytes to base64
  const base64 = btoa(String.fromCharCode(...bytes));

  // Convert base64 to base64url: replace + with -, / with _, remove =
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * ============================================================================
 * HELPER: GENERATE KEY PAIR
 * ============================================================================
 *
 * Ed25519 is an elliptic curve digital signature algorithm. It provides:
 * - Fast signing and verification
 * - Small key and signature sizes (32 bytes / 64 bytes)
 * - High security (128-bit security level)
 *
 * The private key is used to SIGN credentials (kept secret by the issuer).
 * The public key is used to VERIFY signatures (shared publicly).
 *
 * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array}>}
 */
export async function generateKeyPair() {
  // Generate a random 32-byte private key
  const privateKey = ed25519.utils.randomPrivateKey();

  // Derive the corresponding public key
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);

  return { privateKey, publicKey };
}

/**
 * ============================================================================
 * MAIN FUNCTION: ISSUE A VERIFIABLE CREDENTIAL
 * ============================================================================
 *
 * This function creates a signed Verifiable Credential following the W3C
 * VC Data Model 2.0 specification.
 *
 * THE ISSUING PROCESS (5 Steps):
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 1: BUILD CREDENTIAL PAYLOAD                                        │
 * │ Assemble the metadata (@context, type, issuer) and claims               │
 * │ (credentialSubject) into an unsigned credential object.                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 2: CANONICALIZE                                                    │
 * │ Transform the credential to a deterministic format using JCS            │
 * │ (JSON Canonicalization Scheme). This ensures consistent bytes.          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 3: HASH                                                            │
 * │ Create a SHA-256 digest of the canonicalized credential.                │
 * │ This produces a fixed-size fingerprint of the credential.               │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 4: SIGN                                                            │
 * │ Apply Ed25519 digital signature using the issuer's private key.         │
 * │ This creates a unique signature that proves authorship.                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 5: ATTACH PROOF                                                    │
 * │ Add the signature and metadata to the credential as a "proof" object.   │
 * │ This creates the final Verifiable Credential.                           │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @param {Object} params - Issuance parameters
 * @param {string} params.issuerId - DID or URL identifying the issuer
 * @param {Uint8Array} params.privateKey - Issuer's Ed25519 private key
 * @param {Uint8Array} params.publicKey - Issuer's Ed25519 public key
 * @param {Object} params.credentialSubject - The claims about the subject
 * @param {string[]} [params.types] - Additional credential types
 * @param {string} [params.validFrom] - When the credential becomes valid (ISO 8601)
 * @param {string} [params.validUntil] - When the credential expires (ISO 8601)
 * @param {string} [params.credentialId] - Optional unique ID for the credential
 * @returns {Promise<Object>} The signed Verifiable Credential
 */
export async function issueCredential({
  issuerId,
  privateKey,
  publicKey,
  credentialSubject,
  types = [],
  validFrom,
  validUntil,
  credentialId
}) {
  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 1: BUILD THE UNSIGNED CREDENTIAL
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // A Verifiable Credential has several required and optional fields:
  //
  // REQUIRED FIELDS:
  // - @context: Defines the vocabulary (what terms mean)
  // - type: What kind of credential this is
  // - issuer: Who is making these claims
  // - credentialSubject: The actual claims being made
  //
  // OPTIONAL FIELDS:
  // - id: Unique identifier for this credential
  // - validFrom: When the credential becomes valid
  // - validUntil: When the credential expires

  const credential = {
    // @context tells verifiers how to interpret the credential.
    // The VC 2.0 context MUST be the first entry.
    // Think of it like declaring "this document follows these rules."
    '@context': [
      'https://www.w3.org/ns/credentials/v2'
    ],

    // type declares what kind of document this is.
    // "VerifiableCredential" is REQUIRED.
    // Additional types (like "UniversityDegreeCredential") describe the specific kind.
    type: ['VerifiableCredential', ...types],

    // issuer identifies who is making these claims.
    // This should be a DID (Decentralized Identifier) or URL that can be resolved
    // to find the issuer's public keys.
    issuer: issuerId,

    // credentialSubject contains the actual claims.
    // The "id" inside credentialSubject identifies WHO the claims are about.
    // The other properties are the claims themselves.
    credentialSubject: credentialSubject
  };

  // Add optional fields if provided
  if (credentialId) {
    credential.id = credentialId;
  }

  if (validFrom) {
    credential.validFrom = validFrom;
  }

  if (validUntil) {
    credential.validUntil = validUntil;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 2: CANONICALIZE THE CREDENTIAL
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // Why canonicalize? Consider this JSON:
  //   {"name": "Alice", "age": 30}
  //   {"age": 30, "name": "Alice"}
  //
  // These are semantically identical but have different bytes. Without
  // canonicalization, they'd produce different signatures!
  //
  // JCS (JSON Canonicalization Scheme) ensures consistent byte representation.

  const canonicalCredential = canonicalize(credential);

  // Convert to bytes for hashing
  const credentialBytes = new TextEncoder().encode(canonicalCredential);

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 3: HASH THE CREDENTIAL
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // We don't sign the credential directly - we sign its hash.
  // SHA-256 produces a fixed 32-byte "fingerprint" of the data.
  //
  // Benefits of hashing:
  // 1. Fixed size: Regardless of credential size, hash is always 32 bytes
  // 2. One-way: Can't reverse the hash to get original data
  // 3. Collision-resistant: Very hard to find two inputs with same hash

  const hash = sha256(credentialBytes);

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 4: SIGN THE HASH
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // Ed25519 signature takes:
  // - The hash (what we're signing)
  // - The private key (proves we're the issuer)
  //
  // And produces a 64-byte signature that:
  // - Can only be created by someone with the private key
  // - Can be verified by anyone with the public key
  // - Is bound to this specific credential (any change invalidates it)

  const signature = await ed25519.signAsync(hash, privateKey);

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 5: CREATE AND ATTACH THE PROOF
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // The proof object contains everything a verifier needs to check the signature:
  //
  // - type: "DataIntegrityProof" (standard proof type for VC 2.0)
  // - cryptosuite: "eddsa-jcs-2022" (Ed25519 + JCS canonicalization)
  // - verificationMethod: Where to find the public key
  // - proofPurpose: Why this proof was created ("assertionMethod" for credentials)
  // - proofValue: The actual signature (base64url encoded with multibase prefix)
  // - created: When the signature was created
  //
  // The "z" prefix on proofValue indicates base64url encoding (multibase standard)

  const proof = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: `${issuerId}#key-1`,
    proofPurpose: 'assertionMethod',
    proofValue: 'z' + base64urlEncode(signature),
    created: new Date().toISOString()
  };

  // Combine the credential with its proof to create the final Verifiable Credential
  const verifiableCredential = {
    ...credential,
    proof: proof
  };

  return verifiableCredential;
}

/**
 * ============================================================================
 * UTILITY: EXPORT PUBLIC KEY
 * ============================================================================
 *
 * Exports the public key in a format that can be published for verification.
 * This would typically be published at the issuer's DID document.
 *
 * @param {Uint8Array} publicKey - The Ed25519 public key
 * @param {string} issuerId - The issuer's identifier
 * @returns {Object} Public key in multikey format
 */
export function exportPublicKey(publicKey, issuerId) {
  return {
    id: `${issuerId}#key-1`,
    type: 'Multikey',
    controller: issuerId,
    // "z6Mk" prefix indicates Ed25519 public key in multibase/multicodec format
    publicKeyMultibase: 'z6Mk' + base64urlEncode(publicKey)
  };
}
