# HiAE TypeScript Implementation

A TypeScript implementation of the HiAE (High-throughput Authenticated Encryption) algorithm as specified in [draft-pham-cfrg-hiae](https://hiae-aead.github.io/draft-pham-hiae/draft-pham-cfrg-hiae.html).

## Overview

HiAE is a high-throughput authenticated encryption algorithm designed for next-generation wireless systems (6G) and high-speed data transmission applications. This implementation provides:

- Full authenticated encryption with associated data (AEAD)
- Stream cipher mode for keystream generation
- MAC mode for authentication without encryption
- Complete test coverage with all specification test vectors

## Installation

This implementation uses Bun as the JavaScript/TypeScript runtime.

```bash
# Install Bun (if not already installed)
curl -fsSL https://bun.sh/install | bash

# Install dependencies
bun install
```

## Usage

### Basic Encryption/Decryption

```typescript
import { encrypt, decrypt } from './src/index.js';

// 256-bit key (32 bytes)
const key = new Uint8Array(32);
// 128-bit nonce (16 bytes)
const nonce = new Uint8Array(16);

const plaintext = new TextEncoder().encode('Hello, World!');
const associatedData = new TextEncoder().encode('metadata');

// Encrypt
const { ciphertext, tag } = encrypt(plaintext, associatedData, key, nonce);

// Decrypt
const decrypted = decrypt(ciphertext, tag, associatedData, key, nonce);
if (decrypted === null) {
  console.error('Authentication failed!');
} else {
  console.log(new TextDecoder().decode(decrypted));
}
```

### Stream Cipher Mode

```typescript
import { stream } from './src/index.js';

const keystream = stream(1024, key, nonce); // Generate 1024 bytes
```

### MAC Mode

```typescript
import { mac } from './src/index.js';

const data = new TextEncoder().encode('Message to authenticate');
const tag = mac(data, key, nonce);
```

## API Reference

### `encrypt(msg, ad, key, nonce)`
- `msg`: Plaintext to encrypt (Uint8Array)
- `ad`: Associated data to authenticate (Uint8Array)
- `key`: 256-bit encryption key (Uint8Array, 32 bytes)
- `nonce`: 128-bit nonce (Uint8Array, 16 bytes)
- Returns: `{ ciphertext: Uint8Array, tag: Uint8Array }`

### `decrypt(ct, tag, ad, key, nonce)`
- `ct`: Ciphertext to decrypt (Uint8Array)
- `tag`: Authentication tag (Uint8Array, 16 bytes)
- `ad`: Associated data (Uint8Array)
- `key`: 256-bit encryption key (Uint8Array, 32 bytes)
- `nonce`: 128-bit nonce (Uint8Array, 16 bytes)
- Returns: Decrypted plaintext (Uint8Array) or `null` if authentication fails

### `stream(len, key, nonce?)`
- `len`: Length of keystream to generate in bytes
- `key`: 256-bit key (Uint8Array, 32 bytes)
- `nonce`: Optional 128-bit nonce (defaults to zeros)
- Returns: Keystream (Uint8Array)

### `mac(data, key, nonce)`
- `data`: Data to authenticate (Uint8Array)
- `key`: 256-bit key (Uint8Array, 32 bytes)
- `nonce`: 128-bit nonce (Uint8Array, 16 bytes)
- Returns: Authentication tag (Uint8Array, 16 bytes)

## Testing

Run the test suite:

```bash
bun test
```

The test suite includes:
- All 10 test vectors from the specification
- Unit tests for AES primitives and utility functions
- Edge cases and error conditions

## Security Notes

- **Never reuse a nonce** with the same key - this compromises security
- Use cryptographically secure random number generation for keys and nonces

## License

MIT
