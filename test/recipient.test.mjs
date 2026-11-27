// Raw recipient encryption surface. Build first: `yarn build`.
// The recipient tuple is Sapling vector row 2 in the byte order the v1.2.18 daemon accepts
// (see rust/src/recipient.rs for the measured byte-order note).
import assert from 'node:assert/strict';
import test from 'node:test';

import { encryptDescriptor, encryptForRecipient, isValidRecipientEpk } from '../dist/index.js';

const D_HEX = 'f19d9b797e39f337445839';
const PK_D_HEX = 'db4cd2b0aac4f7eb8ca131f16567c445a9555126d3c29f14e3d776e841ae7415';
const CAP = 16_368;

const isHex = (value, length) =>
  typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value);

test('exports the raw recipient surface and keeps the envelope surface', () => {
  assert.equal(typeof encryptForRecipient, 'function');
  assert.equal(typeof isValidRecipientEpk, 'function');
  assert.equal(typeof encryptDescriptor, 'function', 'the envelope surface must still be exported');
});

test('validates the recipient key before any encryption work', () => {
  assert.equal(isValidRecipientEpk(PK_D_HEX), true);
  assert.equal(isValidRecipientEpk(PK_D_HEX.toUpperCase()), true, 'hex is case-insensitive');
  assert.equal(isValidRecipientEpk('00'.repeat(32)), false, 'identity is not a recipient key');
  assert.equal(isValidRecipientEpk(PK_D_HEX.slice(0, 62)), false, 'wrong length');
  assert.equal(isValidRecipientEpk('zz'.repeat(32)), false, 'non-hex');
  assert.equal(isValidRecipientEpk(undefined), false, 'non-string');
});

test('seals raw bytes to a recipient and omits the SSK by default', () => {
  const plaintext = new TextEncoder().encode('raw recipient probe');
  const sealed = encryptForRecipient({ d: D_HEX, pk_d: PK_D_HEX, plaintext });
  assert.ok(isHex(sealed.epk, 64), 'epk is 32 bytes of hex');
  assert.ok(isHex(sealed.ciphertext, (plaintext.length + 16) * 2), 'ciphertext is plaintext + 16-byte tag');
  assert.equal(sealed.ssk, undefined, 'SSK must not leak unless requested');
});

test('returns the SSK only when explicitly requested', () => {
  const sealed = encryptForRecipient({
    d: D_HEX,
    pk_d: PK_D_HEX,
    plaintext: new Uint8Array([1, 2, 3]),
    includeSsk: true,
  });
  assert.ok(isHex(sealed.ssk, 64), 'ssk is 32 bytes of hex');
});

test('two seals of the same payload differ because the ephemeral key is fresh', () => {
  const plaintext = new TextEncoder().encode('same payload');
  const a = encryptForRecipient({ d: D_HEX, pk_d: PK_D_HEX, plaintext });
  const b = encryptForRecipient({ d: D_HEX, pk_d: PK_D_HEX, plaintext });
  assert.notEqual(a.epk, b.epk);
  assert.notEqual(a.ciphertext, b.ciphertext);
});

test('plaintext cap is inclusive at 16,368 and rejected at 16,369', () => {
  const atCap = encryptForRecipient({ d: D_HEX, pk_d: PK_D_HEX, plaintext: new Uint8Array(CAP) });
  assert.equal(atCap.ciphertext.length, (CAP + 16) * 2);

  assert.throws(
    () => encryptForRecipient({ d: D_HEX, pk_d: PK_D_HEX, plaintext: new Uint8Array(CAP + 1) }),
    (error) => error.code === 'INVALID_INPUT',
  );
});

test('rejects malformed recipients and inputs with typed codes', () => {
  const plaintext = new Uint8Array([9]);
  const status = (fn) => {
    try {
      fn();
      return 'no-throw';
    } catch (error) {
      return error.code ?? 'untyped';
    }
  };

  assert.equal(status(() => encryptForRecipient({ d: D_HEX, pk_d: '00'.repeat(32), plaintext })), 'INVALID_RECIPIENT');
  assert.equal(status(() => encryptForRecipient({ d: D_HEX, pk_d: PK_D_HEX.slice(0, 62), plaintext })), 'INVALID_INPUT');
  assert.equal(status(() => encryptForRecipient({ d: 'zz', pk_d: PK_D_HEX, plaintext })), 'INVALID_INPUT');
  assert.equal(status(() => encryptForRecipient({ d: D_HEX, pk_d: PK_D_HEX, plaintext: 'text' })), 'INVALID_INPUT');
  assert.equal(status(() => encryptForRecipient({ d: D_HEX, pk_d: PK_D_HEX, plaintext, includeSsk: 'yes' })), 'INVALID_INPUT');
  assert.equal(status(() => encryptForRecipient(null)), 'INVALID_INPUT');
  assert.equal(status(() => encryptForRecipient()), 'INVALID_INPUT');
});

test('the release namespace exposes no deterministic-ESK entry point', async () => {
  const module = await import('../dist/index.js');
  const suspicious = Object.keys(module).filter((name) => /esk|deterministic|chosen/i.test(name));
  assert.deepEqual(suspicious, [], `unexpected deterministic-ESK export(s): ${suspicious.join(', ')}`);
});
