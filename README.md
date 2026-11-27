# verusid-cmm-encrypt

Write Verus identity **content-multimap** entries in the `flags:13`
public-decrypt envelope shape from TypeScript / JavaScript. TS wrapper +
WASM-Sapling AEAD over a pure-Rust core; produces bytes-in / bytes-out that a
caller composes into an `updateidentity` transaction.

Byte-parity anchored against the daemon's write path
([VerusCoin `pbaasrpc.cpp:16042-16424`](https://github.com/VerusCoin/VerusCoin/blob/d1df9b7d254aacbc12070da48640edf84312200b/src/rpc/pbaasrpc.cpp))
and cross-checked against a live daemon via `decryptdata`. Feature-complete for
the public-decrypt path: chunking (`CNotaryEvidence::BreakApart`), signdata
`SignatureDataKey` attachment, and payloads of arbitrary size.

## Installation

Pin to a specific commit SHA, matching the sibling
[`verusid-cmm-decrypt`](https://github.com/vdappdev2/verusid-cmm-decrypt)
package:

```json
{
  "dependencies": {
    "verusid-cmm-encrypt": "git+https://github.com/vdappdev2/verusid-cmm-encrypt.git#<commit-sha>"
  }
}
```

Node.js ≥ 20. No Rust toolchain required — the WASM artifact is checked into
`dist/` so `yarn add` / `npm install` gives you a ready-to-import package.

## Usage

```typescript
import { encryptDescriptor } from 'verusid-cmm-encrypt';

const result = encryptDescriptor({
  plaintext: { message: 'hello world', ts: Date.now() },
  outerVdxfKey: 'a4ad4638eb96fb16c1a7d3e3cea86bcb7a243ace112286e1f4a64481a34c4100',
  systemId: 'a6ef9ea235635e328124ff3429db9f9e91b64e2d',
  label: 'user_profile',
  dataDepositVoutIndex: 0,
});

// result.cmmEntry: { vdxfKey: Buffer, value: Buffer }
//   → push into Identity.content_multimap
// result.dataDepositOutputScripts: Buffer[]
//   → add each as an EVAL_NOTARY_EVIDENCE transparent output (nValue = 0),
//     contiguously, starting at dataDepositVoutIndex
// result.publishedIvk: Buffer
//   → the 32-byte ivk published on-chain; anyone with it can decrypt
```

Full input shape:

```typescript
type EncryptDescriptorInput = {
  plaintext: string | Uint8Array | Buffer | object;
  // 20-byte binary (LE wire) OR 40-char hex (BE display, from getvdxfid)
  outerVdxfKey: Buffer | Uint8Array | string;
  // 20-byte binary (LE wire) OR 40-char hex (BE display, from getcurrency)
  systemId: Buffer | Uint8Array | string;
  label?: string | null;                   // ≤ 64 UTF-8 bytes, optional
  mimeType?: string | null;                // ≤ 128 bytes, optional
  dataDepositVoutIndex: number;            // u32
  signature?: Buffer | Uint8Array | null;  // optional attached signature
};
```

Full output shape:

```typescript
type EncryptDescriptorOutput = {
  cmmEntry: { vdxfKey: Buffer; value: Buffer };
  dataDepositOutputScripts: Buffer[];  // 1 normally, N when chunking triggers
  publishedIvk: Buffer;
  outerEpk: Buffer;
  ephemeralDiversifier: Buffer;
  ephemeralPkD: Buffer;
};
```

### Chunking

Payloads that produce an `EVAL_NOTARY_EVIDENCE` script larger than 6000 bytes
(≈ 5.7 KB plaintext, after envelope overhead) are transparently split across
multiple tx outputs via a byte-exact port of `CNotaryEvidence::BreakApart`
(`block.cpp:817-842`). `dataDepositOutputScripts.length` reflects the chunk
count; add all outputs contiguously starting at `dataDepositVoutIndex`. The
daemon reader walks MULTIPART outputs and reassembles on retrieval.

### Signature attachment

When you pass `signature`, the encrypt path emits a second
`CVDXFDataDescriptor` appended to the cmm entry value with
`sub_object = 1`, `label = "signature"`, `mime = "application/json"` (matches
the daemon's `signdata` output at `pbaasrpc.cpp:16380-16394`). Both
descriptors are encrypted to the same published IVK — one key decrypts both.

Producing the signature bytes themselves is out of scope. Typical sources:
the daemon's `signdata` RPC, or an offline `CVDXFSignatureData` composition.

### Raw recipient encryption

`encryptForRecipient` encrypts arbitrary bytes to a Sapling recipient without
framing them in a cmm envelope and without publishing any viewing key. It is the
primitive for payloads that will be carried by another container (for example an
off-chain blob protocol) or stored anywhere that is not a Verus identity.

```js
const { epk, ciphertext } = encryptForRecipient({
  d: 'f19d9b797e39f337445839',                                  // 11 bytes, 22 hex
  pk_d: 'db4cd2b0aac4f7eb8ca131f16567c445a9555126d3c29f14e3d776e841ae7415', // 32 bytes, 64 hex
  plaintext,                                                     // Uint8Array, ≤ 16,368 bytes
});
```

The construction is the daemon's own (`pbaas/vdxf.cpp:637-677`): a fresh nonzero
Sapling ephemeral scalar, `epk = ka_derive_public(d, esk)`, `K = KDF_Sapling(ka_agree(pk_d, esk), epk)`,
then ChaCha20-Poly1305-IETF with a zero nonce and no AAD. The crate does not
invent any of it; the envelope path and this path share one implementation, and
the daemon fixture tests prove the envelope bytes still match v1.2.18 exactly.

**Trust properties.** The recipient's incoming viewing key opens the ciphertext —
there is no per-message key beyond that. Anyone holding the IVK for the Sapling
key can decrypt every payload addressed to it, so a service that holds an IVK
holds all traffic to that address. `includeSsk: true` additionally returns the
per-ciphertext symmetric key, which grants access to that one ciphertext alone;
it is off by default and callers should not persist it.

**Size cap.** 16,368 plaintext bytes, inclusive; the ciphertext is plaintext +
16-byte Poly1305 tag. Larger payloads must be chunked by the caller.

**Byte order.** Verus presents Sapling material in `uint256::SetHex` order. The
`pk_d` accepted here is the same byte string the address carries, and the RPC
`ivk` for `decryptdata` must be given byte-reversed relative to the test vectors.
This was measured against v1.2.18, not assumed.

**Error codes.** Every failure is an `Error` with a readonly `code`:

| Code | Meaning |
| --- | --- |
| `INVALID_INPUT` | Malformed request: not an object, non-`Uint8Array` plaintext, non-boolean `includeSsk`, `d`/`pk_d` not the right hex length, plaintext over the cap |
| `INVALID_RECIPIENT` | Well-formed key that is not a usable recipient: non-canonical encoding, identity, wrong subgroup, or a diversifier without a valid `g_d` |
| `ENCRYPT_FAILED` | The core could not complete the encryption |

`isValidRecipientEpk(hex)` performs the key check alone, so callers can validate
a recipient before composing a payload.

## What it does not do

- Not a wallet. No key storage, no fee estimation, no broadcast.
- Not a tx builder. Consumers wire the outputs into a v4 transaction themselves.
- Not a Sapling-address *envelope* path: `encryptDescriptor` still emits only
  `flags:13` public-decrypt with in-band ivk. Recipient-targeted encryption is
  available as the raw `encryptForRecipient` primitive, which produces no
  descriptor and no address handling of its own.
- Does not produce signatures. Callers assemble signatures externally.

## Rust API

The pure-Rust crate at [`rust/`](rust) is also usable directly, without the
TypeScript wrapper or WASM. See [`rust/README.md`](rust/README.md) for the
Rust-focused documentation, including byte-parity guarantees, the daemon
round-trip verification examples, and the layered API.

## Testing

TypeScript wrapper (private tests, run locally):

```
yarn build:wasm && yarn build
node --test test/*.test.mjs
```

Rust crate:

```
yarn test:rust           # or: cd rust && cargo test
```

## License

MIT. See [`LICENSE`](LICENSE).
