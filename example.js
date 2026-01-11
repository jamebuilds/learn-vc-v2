/**
 * ============================================================================
 * EXAMPLE: ISSUING A UNIVERSITY DEGREE CREDENTIAL
 * ============================================================================
 *
 * This example demonstrates how to issue a Verifiable Credential for a
 * university degree. Run with: npm run example
 *
 * The scenario:
 * - Example University wants to issue a digital diploma to Jane Doe
 * - Jane completed a Bachelor of Science in Computer Science
 * - The credential can be verified by anyone (e.g., future employers)
 */

import {
  generateKeyPair,
  issueCredential,
  exportPublicKey
} from './src/issuer.js';

import {
  verifyCredential,
  decodePublicKey
} from './src/verifier.js';

async function main() {
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║     VERIFIABLE CREDENTIALS v2.0 - UNIVERSITY DEGREE EXAMPLE    ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 1: GENERATE ISSUER'S KEY PAIR
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // In production, the university would:
  // 1. Generate these keys once and store them securely
  // 2. Publish the public key in their DID document
  // 3. Keep the private key in a secure vault (HSM, etc.)

  console.log('📝 Step 1: Generating issuer key pair...\n');

  const { privateKey, publicKey } = await generateKeyPair();

  // The issuer's DID (Decentralized Identifier)
  // In production, this would be a real DID like did:web:university.edu
  const issuerId = 'did:example:university123';

  console.log('   Issuer ID:', issuerId);
  console.log('   Public Key (first 16 bytes):', Buffer.from(publicKey.slice(0, 16)).toString('hex') + '...');
  console.log('   Private Key: [KEPT SECRET]\n');

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 2: DEFINE THE CREDENTIAL SUBJECT (CLAIMS)
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // This is what we're claiming about Jane Doe:
  // - She has a specific ID (her DID)
  // - She earned a Bachelor of Science in Computer Science
  // - The degree was conferred on a specific date

  console.log('📝 Step 2: Defining credential subject (claims)...\n');

  const credentialSubject = {
    // The subject's identifier (Jane's DID)
    id: 'did:example:student456',

    // Personal information
    name: 'Jane Doe',

    // The degree information
    degree: {
      type: 'BachelorDegree',
      name: 'Bachelor of Science in Computer Science',
      institution: 'Example University'
    },

    // When the degree was conferred
    dateConferred: '2024-12-15'
  };

  console.log('   Subject ID:', credentialSubject.id);
  console.log('   Name:', credentialSubject.name);
  console.log('   Degree:', credentialSubject.degree.name);
  console.log('   Institution:', credentialSubject.degree.institution);
  console.log('   Date Conferred:', credentialSubject.dateConferred);
  console.log();

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 3: ISSUE THE VERIFIABLE CREDENTIAL
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // This is where the magic happens! The issueCredential function:
  // 1. Builds the credential structure
  // 2. Canonicalizes it (standardizes the format)
  // 3. Hashes it (creates a fingerprint)
  // 4. Signs it (proves the university issued it)
  // 5. Attaches the proof

  console.log('📝 Step 3: Issuing the credential...\n');

  const verifiableCredential = await issueCredential({
    issuerId: issuerId,
    privateKey: privateKey,
    publicKey: publicKey,
    credentialSubject: credentialSubject,

    // Additional type for this specific credential
    types: ['UniversityDegreeCredential'],

    // The credential is valid from today
    validFrom: new Date().toISOString(),

    // Optional: Set an expiration (uncomment to use)
    // validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),

    // Optional: Give the credential a unique ID
    credentialId: 'https://university.example/credentials/12345'
  });

  console.log('   ✅ Credential issued successfully!\n');

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 4: DISPLAY THE VERIFIABLE CREDENTIAL
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('📄 The Verifiable Credential:\n');
  console.log('─'.repeat(70));
  console.log(JSON.stringify(verifiableCredential, null, 2));
  console.log('─'.repeat(70));
  console.log();

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 5: EXPLAIN THE CREDENTIAL STRUCTURE
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('📚 Understanding the Credential Structure:\n');

  console.log('   @context: Defines the vocabulary used in this document');
  console.log('            "https://www.w3.org/ns/credentials/v2" is REQUIRED for VC 2.0\n');

  console.log('   type: Declares what kind of document this is');
  console.log('        "VerifiableCredential" is REQUIRED');
  console.log('        "UniversityDegreeCredential" is our custom type\n');

  console.log('   id: Unique identifier for this specific credential\n');

  console.log('   issuer: Who made these claims (the university)\n');

  console.log('   validFrom: When the credential becomes valid\n');

  console.log('   credentialSubject: The actual claims about Jane\n');

  console.log('   proof: Cryptographic evidence that the university issued this');
  console.log('        - type: "DataIntegrityProof" (standard for VC 2.0)');
  console.log('        - cryptosuite: "eddsa-jcs-2022" (Ed25519 + JCS)');
  console.log('        - verificationMethod: Where to find the public key');
  console.log('        - proofPurpose: Why this proof exists ("assertionMethod")');
  console.log('        - proofValue: The actual signature (base64url encoded)');
  console.log('        - created: When the signature was made\n');

  // ═══════════════════════════════════════════════════════════════════════════
  // BONUS: SHOW THE PUBLIC KEY (for verification)
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('🔑 Issuer\'s Public Key (for verification):\n');
  const publicKeyExport = exportPublicKey(publicKey, issuerId);
  console.log(JSON.stringify(publicKeyExport, null, 2));
  console.log();

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 6: VERIFY THE CREDENTIAL
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // Now let's demonstrate verification! A verifier (e.g., an employer)
  // would receive this credential from Jane and verify it.
  //
  // In production, the verifier would:
  // 1. Receive the credential from the holder (Jane)
  // 2. Look up the issuer's public key from their DID document
  // 3. Verify the signature
  //
  // Here we simulate this using the public key we exported earlier.

  console.log('═'.repeat(70));
  console.log('🔍 Step 6: Verifying the credential...\n');

  // In production, the verifier would fetch this from the issuer's DID document
  // Here we decode it from our exported public key
  const decodedPublicKey = decodePublicKey(publicKeyExport.publicKeyMultibase);

  const verificationResult = await verifyCredential(verifiableCredential, decodedPublicKey);

  console.log('   Verification checks:');
  console.log(`     ├─ Has proof object: ${verificationResult.checks.hasProof ? '✅' : '❌'}`);
  console.log(`     ├─ Proof type valid: ${verificationResult.checks.proofType ? '✅' : '❌'}`);
  console.log(`     ├─ Cryptosuite valid: ${verificationResult.checks.cryptosuite ? '✅' : '❌'}`);
  console.log(`     └─ Signature valid: ${verificationResult.checks.signatureValid ? '✅' : '❌'}`);
  console.log();

  if (verificationResult.verified) {
    console.log('   ✅ CREDENTIAL VERIFIED SUCCESSFULLY!\n');
    console.log('   This means:');
    console.log('     • The credential was signed by the issuer');
    console.log('     • The credential has not been tampered with');
    console.log('     • The signature is mathematically valid\n');
  } else {
    console.log('   ❌ VERIFICATION FAILED');
    console.log('   Errors:', verificationResult.errors);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 7: DEMONSTRATE TAMPER DETECTION
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // Let's show what happens if someone tries to modify the credential.
  // The signature verification will fail because the hash won't match.

  console.log('═'.repeat(70));
  console.log('🛡️  Step 7: Demonstrating tamper detection...\n');

  // Create a tampered copy of the credential
  const tamperedCredential = JSON.parse(JSON.stringify(verifiableCredential));
  tamperedCredential.credentialSubject.degree.name = 'Doctor of Philosophy in Computer Science';

  console.log('   Attempting to verify a tampered credential...');
  console.log('   (Changed degree from "Bachelor" to "Doctor of Philosophy")\n');

  const tamperedResult = await verifyCredential(tamperedCredential, decodedPublicKey);

  console.log('   Verification checks:');
  console.log(`     ├─ Has proof object: ${tamperedResult.checks.hasProof ? '✅' : '❌'}`);
  console.log(`     ├─ Proof type valid: ${tamperedResult.checks.proofType ? '✅' : '❌'}`);
  console.log(`     ├─ Cryptosuite valid: ${tamperedResult.checks.cryptosuite ? '✅' : '❌'}`);
  console.log(`     └─ Signature valid: ${tamperedResult.checks.signatureValid ? '✅' : '❌'}`);
  console.log();

  if (!tamperedResult.verified) {
    console.log('   ❌ TAMPERED CREDENTIAL DETECTED!\n');
    console.log('   The signature verification failed because:');
    console.log('     • The credential content was modified');
    console.log('     • The hash no longer matches the signed hash');
    console.log('     • Any change, no matter how small, invalidates the signature\n');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('═'.repeat(70));
  console.log('📚 SUMMARY: THE COMPLETE VC LIFECYCLE');
  console.log('═'.repeat(70));
  console.log(`
┌─────────────────────────────────────────────────────────────────────────┐
│                         ISSUANCE (Steps 1-5)                            │
├─────────────────────────────────────────────────────────────────────────┤
│  1. Generate key pair (Ed25519)                                         │
│  2. Build credential with claims                                        │
│  3. Canonicalize (JCS) → deterministic bytes                            │
│  4. Hash (SHA-256) → fixed-size fingerprint                             │
│  5. Sign hash with private key → proof                                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         VERIFICATION (Step 6)                           │
├─────────────────────────────────────────────────────────────────────────┤
│  1. Extract proof from credential                                       │
│  2. Remove proof to get unsigned credential                             │
│  3. Canonicalize (same as issuance)                                     │
│  4. Hash (same as issuance)                                             │
│  5. Verify signature with public key                                    │
│  6. If valid → credential is authentic!                                 │
└─────────────────────────────────────────────────────────────────────────┘
`);
}

// Run the example
main().catch(console.error);
