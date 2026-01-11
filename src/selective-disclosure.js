/**
 * ============================================================================
 * SELECTIVE DISCLOSURE FOR VERIFIABLE CREDENTIALS
 * ============================================================================
 *
 * This module implements selective disclosure using a salted hash approach,
 * similar to SD-JWT. It allows credential holders to reveal only specific
 * claims while proving the issuer signed the complete credential.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-08.html
 *
 * ============================================================================
 * WHY SELECTIVE DISCLOSURE?
 * ============================================================================
 *
 * Consider this scenario: Jane has a university degree credential containing:
 *   - Her name
 *   - Her degree type (Bachelor's)
 *   - Her specific degree (Computer Science)
 *   - The date conferred
 *
 * An employer only needs to verify she has a Bachelor's degree. Without
 * selective disclosure, Jane must reveal ALL her information.
 *
 * With selective disclosure:
 *   - Jane can prove she has a Bachelor's degree
 *   - WITHOUT revealing her name or other details
 *   - The employer can still verify the university signed this claim
 *
 * ============================================================================
 * HOW IT WORKS (Salted Hash Approach)
 * ============================================================================
 *
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │ ISSUANCE                                                                │
 *   │                                                                         │
 *   │   Original field:  name = "Jane Doe"                                    │
 *   │                         │                                               │
 *   │                         ▼                                               │
 *   │   Generate salt:   random 16 bytes                                      │
 *   │                         │                                               │
 *   │                         ▼                                               │
 *   │   Compute hash:    SHA-256(salt + "name" + "Jane Doe")                  │
 *   │                         │                                               │
 *   │                         ▼                                               │
 *   │   Store in credential: { "_sd": "zK7p4..." }                            │
 *   │                                                                         │
 *   │   Give holder both:                                                     │
 *   │   - Credential (with hashes)                                            │
 *   │   - Disclosures (salt + original values)                                │
 *   └─────────────────────────────────────────────────────────────────────────┘
 *
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │ PRESENTATION (by Holder)                                                │
 *   │                                                                         │
 *   │   Holder selects which fields to reveal:                                │
 *   │   - Include disclosure for those fields only                            │
 *   │   - Other fields stay as hashes (verifier can't see them)               │
 *   └─────────────────────────────────────────────────────────────────────────┘
 *
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │ VERIFICATION                                                            │
 *   │                                                                         │
 *   │   1. Verify credential signature (issuer signed it)                     │
 *   │   2. For each disclosed field:                                          │
 *   │      - Recompute: SHA-256(salt + path + value)                          │
 *   │      - Check it matches the hash in the credential                      │
 *   │   3. If match: the disclosed value is authentic!                        │
 *   └─────────────────────────────────────────────────────────────────────────┘
 *
 * ============================================================================
 */

import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { verifyCredential } from './verifier.js';

// Required: Configure ed25519 to use sha512 for hashing
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

/**
 * ============================================================================
 * HELPER: JSON CANONICALIZATION SCHEME (JCS)
 * ============================================================================
 *
 * Ensures consistent byte representation for hashing.
 * Same implementation as in issuer.js and verifier.js.
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
 * HELPER: BASE64URL ENCODING/DECODING
 * ============================================================================
 */
function base64urlEncode(bytes) {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64urlDecode(str) {
  let base64 = str
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes;
}

/**
 * ============================================================================
 * HELPER: GENERATE CRYPTOGRAPHIC SALT
 * ============================================================================
 *
 * Generates a random 16-byte (128-bit) salt for hashing disclosable fields.
 *
 * Why 16 bytes?
 * - 128 bits provides sufficient entropy against brute-force attacks
 * - Even for low-entropy values (like "yes"/"no"), the salt prevents guessing
 * - Matches SD-JWT recommendations
 *
 * @returns {Uint8Array} 16 random bytes
 */
function generateSalt() {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * ============================================================================
 * HELPER: COMPUTE DISCLOSURE HASH
 * ============================================================================
 *
 * Creates a hash that cryptographically binds a salt, field path, and value.
 *
 * THE HASH STRUCTURE:
 *   SHA-256( salt || utf8(path) || utf8(canonicalize(value)) )
 *
 * Why include the path?
 *   Without the path, an attacker could potentially swap hashes between fields.
 *   Including the path ensures each hash is bound to its specific location.
 *
 * Why canonicalize the value?
 *   Ensures objects and arrays always produce the same hash regardless of
 *   property ordering or formatting.
 *
 * @param {Uint8Array} salt - 16-byte random salt
 * @param {string} path - JSON path to the field (e.g., "credentialSubject.name")
 * @param {any} value - The field value (string, number, object, array)
 * @returns {string} Base64url-encoded hash
 */
function computeDisclosureHash(salt, path, value) {
  // Canonicalize the value to ensure consistent hashing
  const canonicalValue = canonicalize(value);

  // Concatenate: salt + path bytes + value bytes
  const pathBytes = new TextEncoder().encode(path);
  const valueBytes = new TextEncoder().encode(canonicalValue);

  const combined = new Uint8Array(salt.length + pathBytes.length + valueBytes.length);
  combined.set(salt, 0);
  combined.set(pathBytes, salt.length);
  combined.set(valueBytes, salt.length + pathBytes.length);

  // Hash and encode
  const hash = sha256(combined);
  return base64urlEncode(hash);
}

/**
 * ============================================================================
 * HELPER: GET VALUE AT PATH
 * ============================================================================
 *
 * Navigates an object using dot-notation path.
 * Example: getValueAtPath(obj, "credentialSubject.degree.type")
 *
 * @param {Object} obj - The object to navigate
 * @param {string} path - Dot-notation path
 * @returns {any} The value at the path, or undefined
 */
function getValueAtPath(obj, path) {
  const parts = path.split('.');
  let current = obj;

  for (const part of parts) {
    if (current === undefined || current === null) {
      return undefined;
    }
    current = current[part];
  }

  return current;
}

/**
 * ============================================================================
 * HELPER: SET VALUE AT PATH
 * ============================================================================
 *
 * Sets a value in an object at a dot-notation path.
 * Creates intermediate objects if needed.
 *
 * @param {Object} obj - The object to modify
 * @param {string} path - Dot-notation path
 * @param {any} value - The value to set
 */
function setValueAtPath(obj, path, value) {
  const parts = path.split('.');
  let current = obj;

  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (!(part in current)) {
      current[part] = {};
    }
    current = current[part];
  }

  current[parts[parts.length - 1]] = value;
}

/**
 * ============================================================================
 * HELPER: DEEP CLONE
 * ============================================================================
 *
 * Creates a deep copy of an object to avoid mutating the original.
 */
function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * ============================================================================
 * MAIN FUNCTION: ISSUE SELECTIVE DISCLOSURE CREDENTIAL
 * ============================================================================
 *
 * Creates a Verifiable Credential with selective disclosure capability.
 *
 * THE ISSUANCE PROCESS:
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 1: IDENTIFY DISCLOSABLE FIELDS                                     │
 * │ The caller specifies which fields can be selectively disclosed          │
 * │ using JSON path strings like "credentialSubject.name"                   │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 2: GENERATE SALTS AND CREATE DISCLOSURES                           │
 * │ For each disclosable field:                                             │
 * │ - Generate random 16-byte salt                                          │
 * │ - Create disclosure: { salt, path, value }                              │
 * │ - Compute hash: SHA-256(salt + path + value)                            │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 3: REPLACE VALUES WITH HASHES                                      │
 * │ In the credential, replace disclosable values with: { "_sd": hash }     │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 4: SIGN THE CREDENTIAL                                             │
 * │ Sign the credential containing hashes (not original values)             │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @param {Object} params
 * @param {string} params.issuerId - DID identifying the issuer
 * @param {Uint8Array} params.privateKey - Issuer's Ed25519 private key
 * @param {Uint8Array} params.publicKey - Issuer's Ed25519 public key
 * @param {Object} params.credentialSubject - The claims about the subject
 * @param {string[]} params.disclosablePaths - Paths of fields that can be selectively disclosed
 * @param {string[]} [params.types] - Additional credential types
 * @param {string} [params.validFrom] - When the credential becomes valid
 * @param {string} [params.validUntil] - When the credential expires
 * @param {string} [params.credentialId] - Optional unique ID
 * @returns {Promise<{credential: Object, disclosures: Array}>}
 */
export async function issueSDCredential({
  issuerId,
  privateKey,
  publicKey,
  credentialSubject,
  disclosablePaths,
  types = [],
  validFrom,
  validUntil,
  credentialId
}) {
  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 1: VALIDATE AND PREPARE
  // ═══════════════════════════════════════════════════════════════════════════

  // Deep clone to avoid mutating the input
  const modifiedSubject = deepClone(credentialSubject);

  // Validate all paths exist
  for (const path of disclosablePaths) {
    const value = getValueAtPath({ credentialSubject: modifiedSubject }, path);
    if (value === undefined) {
      throw new Error(`Disclosable path "${path}" not found in credential subject`);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 2: GENERATE DISCLOSURES AND REPLACE WITH HASHES
  // ═══════════════════════════════════════════════════════════════════════════

  const disclosures = [];

  for (const path of disclosablePaths) {
    // Get the original value
    const value = getValueAtPath({ credentialSubject: modifiedSubject }, path);

    // Generate a random salt
    const salt = generateSalt();

    // Compute the hash
    const hash = computeDisclosureHash(salt, path, value);

    // Create the disclosure (holder will need this to reveal the value)
    disclosures.push({
      salt: base64urlEncode(salt),
      path: path,
      value: value
    });

    // Replace the value with the hash marker
    // The path starts with "credentialSubject." so we need to remove that prefix
    // when setting in modifiedSubject
    const subjectPath = path.replace('credentialSubject.', '');
    setValueAtPath(modifiedSubject, subjectPath, { '_sd': hash });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 3: BUILD THE UNSIGNED CREDENTIAL
  // ═══════════════════════════════════════════════════════════════════════════

  const credential = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2'
    ],
    type: ['VerifiableCredential', ...types],
    issuer: issuerId,
    credentialSubject: modifiedSubject,
    // Indicate this is an SD credential and which hash algorithm is used
    _sd_alg: 'sha-256'
  };

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
  // STEP 4: SIGN THE CREDENTIAL
  // ═══════════════════════════════════════════════════════════════════════════

  // Canonicalize and hash
  const canonicalCredential = canonicalize(credential);
  const credentialBytes = new TextEncoder().encode(canonicalCredential);
  const hash = sha256(credentialBytes);

  // Sign
  const signature = await ed25519.signAsync(hash, privateKey);

  // Attach proof
  const proof = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: `${issuerId}#key-1`,
    proofPurpose: 'assertionMethod',
    proofValue: 'z' + base64urlEncode(signature),
    created: new Date().toISOString()
  };

  const signedCredential = {
    ...credential,
    proof: proof
  };

  return {
    credential: signedCredential,
    disclosures: disclosures
  };
}

/**
 * ============================================================================
 * HOLDER FUNCTION: CREATE SELECTIVE DISCLOSURE PRESENTATION
 * ============================================================================
 *
 * The holder uses this function to create a presentation that reveals only
 * specific fields to the verifier.
 *
 * PRIVACY PROPERTIES:
 * - Only selected disclosures are included in the presentation
 * - Non-disclosed fields remain as hashes in the credential
 * - The verifier cannot determine values of non-disclosed fields
 * - The signature remains valid (it covers the hashes, not original values)
 *
 * @param {Object} credential - The SD-enabled credential (with hashes)
 * @param {Array} allDisclosures - All disclosures received from issuance
 * @param {string[]} pathsToReveal - JSON paths of fields to disclose
 * @returns {Object} Presentation with credential and selected disclosures
 */
export function createSDPresentation(credential, allDisclosures, pathsToReveal) {
  // Filter disclosures to only include the paths the holder wants to reveal
  const selectedDisclosures = allDisclosures.filter(d =>
    pathsToReveal.includes(d.path)
  );

  // Validate that all requested paths have disclosures
  for (const path of pathsToReveal) {
    const found = allDisclosures.find(d => d.path === path);
    if (!found) {
      throw new Error(`No disclosure found for path "${path}"`);
    }
  }

  return {
    credential: credential,
    disclosures: selectedDisclosures
  };
}

/**
 * ============================================================================
 * VERIFIER FUNCTION: VERIFY SELECTIVE DISCLOSURE PRESENTATION
 * ============================================================================
 *
 * Verifies a selective disclosure presentation by:
 * 1. Verifying the credential signature (proves issuer signed it)
 * 2. Verifying each disclosure matches its hash in the credential
 *
 * THE VERIFICATION PROCESS:
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 1: VERIFY CREDENTIAL SIGNATURE                                     │
 * │ Confirms the issuer signed this credential (with hashes)                │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 2: VERIFY EACH DISCLOSURE                                          │
 * │ For each disclosed field:                                               │
 * │ - Decode the salt                                                       │
 * │ - Recompute: SHA-256(salt + path + value)                               │
 * │ - Check it matches the hash in the credential                           │
 * └─────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ STEP 3: RETURN VERIFIED CLAIMS                                          │
 * │ Only claims that passed verification are returned                       │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @param {Object} presentation - The SD presentation
 * @param {Object} presentation.credential - The signed SD credential
 * @param {Array} presentation.disclosures - Disclosed field salt/value pairs
 * @param {Uint8Array} publicKey - The issuer's public key
 * @returns {Promise<Object>} Verification result with disclosed claims
 */
export async function verifySDPresentation(presentation, publicKey) {
  const result = {
    verified: false,
    checks: {
      credentialSignature: false,
      disclosuresValid: false
    },
    disclosedClaims: {},
    errors: []
  };

  const { credential, disclosures } = presentation;

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 1: VERIFY CREDENTIAL SIGNATURE
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // This confirms that the issuer signed the credential containing these hashes.
  // Even though we're only seeing some disclosed values, the signature covers
  // ALL the hashes in the credential.

  const credentialResult = await verifyCredential(credential, publicKey);

  if (!credentialResult.verified) {
    result.errors.push('Credential signature verification failed: ' + credentialResult.errors.join(', '));
    return result;
  }

  result.checks.credentialSignature = true;

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 2: VERIFY EACH DISCLOSURE
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // For each disclosure, we:
  // 1. Recompute the hash using the provided salt and value
  // 2. Find the hash stored in the credential at that path
  // 3. Compare them - they must match exactly

  let allDisclosuresValid = true;

  for (const disclosure of disclosures) {
    const { salt: saltBase64, path, value } = disclosure;

    // Decode the salt
    const salt = base64urlDecode(saltBase64);

    // Recompute the hash
    const computedHash = computeDisclosureHash(salt, path, value);

    // Find the hash in the credential
    // Path is like "credentialSubject.name", need to get the _sd value
    const sdObject = getValueAtPath(credential, path);

    if (!sdObject || typeof sdObject !== 'object' || !sdObject._sd) {
      result.errors.push(`Path "${path}" does not contain a selective disclosure hash`);
      allDisclosuresValid = false;
      continue;
    }

    const storedHash = sdObject._sd;

    // Compare hashes
    if (computedHash !== storedHash) {
      result.errors.push(`Disclosure for "${path}" does not match credential hash (possible tampering)`);
      allDisclosuresValid = false;
      continue;
    }

    // Disclosure verified! Add to disclosed claims
    result.disclosedClaims[path] = value;
  }

  result.checks.disclosuresValid = allDisclosuresValid;

  // Overall verification succeeds only if both checks pass
  result.verified = result.checks.credentialSignature && result.checks.disclosuresValid;

  return result;
}
