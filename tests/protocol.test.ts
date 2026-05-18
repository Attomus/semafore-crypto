import { describe, expect, it } from 'vitest';

import {
  bytesToUtf8,
  decryptMessage,
  encryptMessage,
  generateEd25519KeyPair,
  generateIdentityKeyPair,
  generateOneTimePrekey,
  generateSignedPrekey,
  initReceiverSession,
  initSenderSession,
  parseDrV1Header,
  type KeyBundle
} from '../src/index.js';

function createSessions() {
  const aliceIdentity = generateIdentityKeyPair();
  const bobIdentity = generateIdentityKeyPair();
  const bobSigning = generateEd25519KeyPair();
  const bobSpk = generateSignedPrekey(bobSigning.secretKey, 'spk-live');
  const bobOpk = generateOneTimePrekey('opk-live');
  const recipientBundle: KeyBundle = {
    identityAgreementKey: bobIdentity.publicKey,
    identitySigningKey: bobSigning.publicKey,
    signedPrekey: {
      keyId: bobSpk.keyId,
      publicKey: bobSpk.publicKey,
      signature: bobSpk.signature
    },
    oneTimePrekey: {
      keyId: bobOpk.keyId,
      publicKey: bobOpk.publicKey
    }
  };

  const alice = initSenderSession({
    myIdentity: aliceIdentity,
    recipientBundle
  });
  const first = encryptMessage(alice, 'first contact');
  const bobInit = initReceiverSession({
    myIdentity: bobIdentity,
    senderIdentityPublicKey: aliceIdentity.publicKey,
    envelope: first,
    signedPrekeyLookup: () => bobSpk,
    oneTimePrekeyLookup: () => bobOpk
  });

  expect(bytesToUtf8(decryptMessage(bobInit.session, first))).toBe(
    'first contact'
  );
  return { alice, bob: bobInit.session };
}

describe('protocol sessions', () => {
  it('round-trips SMX1 first contact and SMD1 follow-up messages', () => {
    const { alice, bob } = createSessions();

    const second = encryptMessage(alice, 'second message');
    expect(second.kind).toBe('smd1');
    expect(bytesToUtf8(decryptMessage(bob, second))).toBe('second message');

    const reply = encryptMessage(bob, 'reply after receiver ratchet');
    expect(reply.kind).toBe('smd1');
    expect(bytesToUtf8(decryptMessage(alice, reply))).toBe(
      'reply after receiver ratchet'
    );
  });

  it('uses skipped message keys for out-of-order messages within one ratchet chain', () => {
    const { alice, bob } = createSessions();
    const second = encryptMessage(alice, 'second message');
    const third = encryptMessage(alice, 'third message');

    expect(parseDrV1Header(third.frameBytes).messageNumber).toBe(2);
    expect(bytesToUtf8(decryptMessage(bob, third))).toBe('third message');
    expect(bob.skippedMessageKeys).toHaveLength(1);
    expect(bytesToUtf8(decryptMessage(bob, second))).toBe('second message');
    expect(bob.skippedMessageKeys).toHaveLength(0);
  });

  it('rejects replayed SMD1 messages after the skipped key is consumed', () => {
    const { alice, bob } = createSessions();
    const second = encryptMessage(alice, 'second message');

    expect(bytesToUtf8(decryptMessage(bob, second))).toBe('second message');
    expect(() => decryptMessage(bob, second)).toThrow();
  });
});
