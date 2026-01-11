/**
 * ============================================================================
 * EXAMPLE: SELECTIVE DISCLOSURE - PRIVACY-PRESERVING CREDENTIALS
 * ============================================================================
 *
 * This example demonstrates how selective disclosure allows credential holders
 * to reveal only specific claims while proving the issuer signed them.
 *
 * THE SCENARIO:
 * - Jane Doe has a university degree credential
 * - An employer wants to verify she has a Bachelor's degree
 * - Jane wants to prove her degree type WITHOUT revealing her name
 *
 * Run with: node example-sd.js
 */

import { generateKeyPair, exportPublicKey } from './src/issuer.js';
import { decodePublicKey } from './src/verifier.js';
import {
  issueSDCredential,
  createSDPresentation,
  verifySDPresentation
} from './src/selective-disclosure.js';

async function main() {
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║     SELECTIVE DISCLOSURE - PRIVACY-PRESERVING CREDENTIALS      ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  // ═══════════════════════════════════════════════════════════════════════════
  // BACKGROUND: THE PRIVACY PROBLEM
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('═'.repeat(70));
  console.log('📚 THE PRIVACY PROBLEM WITH TRADITIONAL CREDENTIALS');
  console.log('═'.repeat(70));
  console.log(`
Without selective disclosure, verifying a single claim requires
revealing the ENTIRE credential:

  ┌────────────────────────────────────────────────────────────────┐
  │  Jane's Full Credential                                        │
  │  ────────────────────────────────────────────────────────────  │
  │  Name: Jane Doe                    ◄── Must reveal (unwanted)  │
  │  Degree Type: Bachelor             ◄── Want to prove this      │
  │  Degree Name: BS in Computer Sci   ◄── Must reveal (unwanted)  │
  │  Date: 2024-12-15                  ◄── Must reveal (unwanted)  │
  └────────────────────────────────────────────────────────────────┘

With selective disclosure, Jane can prove ONLY what's needed:

  ┌────────────────────────────────────────────────────────────────┐
  │  Jane's Presentation (Selective Disclosure)                    │
  │  ────────────────────────────────────────────────────────────  │
  │  Name: [HIDDEN - hash only]                                    │
  │  Degree Type: Bachelor             ◄── Revealed & verified!    │
  │  Degree Name: [HIDDEN - hash only]                             │
  │  Date: [HIDDEN - hash only]                                    │
  └────────────────────────────────────────────────────────────────┘
`);

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 1: SETUP - GENERATE ISSUER KEYS
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('═'.repeat(70));
  console.log('🔑 Step 1: University generates signing keys');
  console.log('═'.repeat(70));

  const { privateKey, publicKey } = await generateKeyPair();
  const issuerId = 'did:example:university123';

  console.log(`   Issuer: ${issuerId}`);
  console.log('   Keys generated successfully\n');

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 2: ISSUE CREDENTIAL WITH SELECTIVE DISCLOSURE
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('═'.repeat(70));
  console.log('📜 Step 2: University issues SD-enabled credential to Jane');
  console.log('═'.repeat(70));

  const credentialSubject = {
    id: 'did:example:jane456',
    name: 'Jane Doe',
    degree: {
      type: 'BachelorDegree',
      name: 'Bachelor of Science in Computer Science'
    },
    dateConferred: '2024-12-15'
  };

  console.log('\n   Original credential subject (before SD processing):');
  console.log('   ' + JSON.stringify(credentialSubject, null, 2).split('\n').join('\n   '));

  // Issue with selective disclosure - specify which fields can be hidden
  const sdResult = await issueSDCredential({
    issuerId,
    privateKey,
    publicKey,
    credentialSubject,
    disclosablePaths: [
      'credentialSubject.name',
      'credentialSubject.degree.type',
      'credentialSubject.degree.name',
      'credentialSubject.dateConferred'
    ],
    types: ['UniversityDegreeCredential'],
    validFrom: new Date().toISOString()
  });

  console.log('\n   SD Credential issued! Notice the hashed fields:\n');
  console.log('   ' + JSON.stringify(sdResult.credential, null, 2).split('\n').join('\n   '));

  console.log('\n   Jane also receives disclosures (kept private):');
  console.log('   ─'.repeat(35));
  for (const d of sdResult.disclosures) {
    console.log(`   Path: ${d.path}`);
    console.log(`   Value: ${JSON.stringify(d.value)}`);
    console.log(`   Salt: ${d.salt.substring(0, 20)}...`);
    console.log('   ─'.repeat(35));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 3: JANE CREATES A PRESENTATION (REVEALING ONLY DEGREE TYPE)
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('\n' + '═'.repeat(70));
  console.log('📤 Step 3: Jane creates presentation for employer');
  console.log('═'.repeat(70));

  console.log(`
   Scenario: An employer asks "Do you have a Bachelor's degree?"

   Jane wants to prove she has a Bachelor's degree WITHOUT revealing:
   - Her full name
   - The specific degree name
   - The graduation date

   She selects to reveal ONLY: credentialSubject.degree.type
`);

  const presentation = createSDPresentation(
    sdResult.credential,
    sdResult.disclosures,
    ['credentialSubject.degree.type']  // Only reveal degree type!
  );

  console.log('   Presentation created with:');
  console.log(`   - Full signed credential (hashes intact)`);
  console.log(`   - 1 disclosure (for degree.type only)`);
  console.log(`   - Other fields remain hidden\n`);
  console.log('   ' + JSON.stringify(presentation, null, 2).split('\n').join('\n   '));

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 4: EMPLOYER VERIFIES THE PRESENTATION
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('═'.repeat(70));
  console.log('🔍 Step 4: Employer verifies the presentation');
  console.log('═'.repeat(70));

  // In production, the employer would look up the public key from the issuer's DID document
  const publicKeyExport = exportPublicKey(publicKey, issuerId);
  const decodedPublicKey = decodePublicKey(publicKeyExport.publicKeyMultibase);

  const verifyResult = await verifySDPresentation(presentation, decodedPublicKey);

  console.log('\n   Verification process:');
  console.log(`   1. Check credential signature: ${verifyResult.checks.credentialSignature ? '✅ Valid' : '❌ Invalid'}`);
  console.log(`   2. Check disclosures match hashes: ${verifyResult.checks.disclosuresValid ? '✅ Valid' : '❌ Invalid'}`);

  if (verifyResult.verified) {
    console.log('\n   ✅ PRESENTATION VERIFIED SUCCESSFULLY!\n');

    console.log('   What the employer CAN see (verified claims):');
    console.log('   ┌────────────────────────────────────────────────────┐');
    for (const [path, value] of Object.entries(verifyResult.disclosedClaims)) {
      const shortPath = path.replace('credentialSubject.', '');
      console.log(`   │  ${shortPath}: ${JSON.stringify(value)}`);
    }
    console.log('   └────────────────────────────────────────────────────┘');

    console.log('\n   What the employer CANNOT see (hidden):');
    console.log('   ┌────────────────────────────────────────────────────┐');
    console.log('   │  name: [HIDDEN - only hash visible]');
    console.log('   │  degree.name: [HIDDEN - only hash visible]');
    console.log('   │  dateConferred: [HIDDEN - only hash visible]');
    console.log('   └────────────────────────────────────────────────────┘');
  } else {
    console.log('\n   ❌ VERIFICATION FAILED');
    console.log('   Errors:', verifyResult.errors);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 5: DEMONSTRATE TAMPER DETECTION
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('\n' + '═'.repeat(70));
  console.log('🛡️  Step 5: Demonstrate tamper detection');
  console.log('═'.repeat(70));

  console.log(`
   What if someone tries to lie about their degree type?

   Let's create a tampered presentation where someone claims to have
   a "DoctoralDegree" instead of "BachelorDegree"...
`);

  // Create a tampered disclosure
  const tamperedPresentation = {
    credential: presentation.credential,
    disclosures: [{
      ...presentation.disclosures[0],
      value: 'DoctoralDegree'  // Lie about the degree type!
    }]
  };

  const tamperedResult = await verifySDPresentation(tamperedPresentation, decodedPublicKey);

  console.log('   Verification of tampered presentation:');
  console.log(`   1. Credential signature: ${tamperedResult.checks.credentialSignature ? '✅ Valid' : '❌ Invalid'}`);
  console.log(`   2. Disclosures match: ${tamperedResult.checks.disclosuresValid ? '✅ Valid' : '❌ Invalid'}`);
  console.log(`\n   Overall: ${tamperedResult.verified ? '✅ Verified' : '❌ REJECTED'}`);

  if (tamperedResult.errors.length > 0) {
    console.log('\n   Why it failed:');
    for (const error of tamperedResult.errors) {
      console.log(`   - ${error}`);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('\n' + '═'.repeat(70));
  console.log('📚 SUMMARY: HOW SELECTIVE DISCLOSURE WORKS');
  console.log('═'.repeat(70));
  console.log(`
┌─────────────────────────────────────────────────────────────────────────┐
│                        THE SALTED HASH APPROACH                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ISSUANCE (University)                                                  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  For each disclosable field:                                      │  │
│  │    1. Generate random salt (16 bytes)                             │  │
│  │    2. Hash = SHA-256(salt + field_path + value)                   │  │
│  │    3. Replace value with { "_sd": hash }                          │  │
│  │    4. Store disclosure = { salt, path, value }                    │  │
│  │  Sign the credential with hashes                                  │  │
│  │  Give holder: credential + all disclosures                        │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  PRESENTATION (Holder)                                                  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Choose which fields to reveal                                    │  │
│  │  Include disclosures for only those fields                        │  │
│  │  Send: credential + selected disclosures                          │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  VERIFICATION (Employer)                                                │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  1. Verify credential signature (issuer signed it)                │  │
│  │  2. For each disclosure:                                          │  │
│  │     - Recompute: SHA-256(salt + path + value)                     │  │
│  │     - Check it matches hash in credential                         │  │
│  │  3. If all match: disclosed values are authentic!                 │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  KEY INSIGHT: The salt prevents brute-force guessing of hidden values.  │
│  Without the salt, you cannot reverse the hash.                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
`);
}

// Run the example
main().catch(console.error);
