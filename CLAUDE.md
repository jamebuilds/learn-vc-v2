# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Educational implementation of W3C Verifiable Credentials Data Model 2.0 using Ed25519 cryptography. This is a pure Node.js ES6 module library focused on demonstrating credential issuance.

## Commands

```bash
npm install        # Install dependencies
npm run example    # Run the credential issuance demonstration
```

No build, test, or lint scripts are configured—this is an intentionally minimal educational project.

## Architecture

### Core Module: `src/issuer.js`

Three exported functions:

1. **`generateKeyPair()`** - Creates Ed25519 public/private key pair using `@noble/ed25519`

2. **`issueCredential(params)`** - Main credential issuance with 5-step process:
   - Build unsigned credential structure
   - Canonicalize with JSON Canonicalization Scheme (RFC 8785)
   - Hash with SHA-256
   - Sign with Ed25519
   - Attach DataIntegrityProof with `eddsa-jcs-2022` cryptosuite

3. **`exportPublicKey(publicKey, issuerId)`** - Formats public key in multikey format for DID documents

### Helper Functions (internal)

- `canonicalize(obj)` - JSON Canonicalization Scheme implementation
- `base64urlEncode(bytes)` - URL-safe base64 encoding

### Example: `example.js`

Demonstrates issuing a university degree credential with key generation, credential subject definition, and formatted output explanation.

## Cryptographic Stack

- **Signature:** Ed25519 via `@noble/ed25519`
- **Hashing:** SHA-256 via `@noble/hashes`
- **Encoding:** Base64URL (RFC 4648)
- **Serialization:** JSON Canonicalization Scheme (RFC 8785)

## W3C VC 2.0 Credential Structure

Output follows W3C Verifiable Credentials Data Model 2.0 with `@context`, `type`, `issuer`, `credentialSubject`, and `proof` containing the DataIntegrityProof signature.
