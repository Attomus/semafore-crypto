import { describe, expect, it } from 'vitest';

import {
  bytesToUtf8,
  decryptMessage,
  encodeSmx1Envelope,
  encryptMessage,
  generateEd25519KeyPair,
  generateIdentityKeyPair,
  generateOneTimePrekey,
  generateSignedPrekey,
  initReceiverSession,
  initSenderSession,
  parseSmx1Envelope,
  type LocalOneTimePrekey,
  type LocalSignedPrekey,
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
    localIdentity: aliceIdentity,
    recipientBundle
  });
  const first = encryptMessage(alice, 'first contact');
  const bobInit = initReceiverSession({
    localIdentity: bobIdentity,
    peerIdentityPublicKey: aliceIdentity.publicKey,
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

function lookupOrThrow<T extends { keyId: string }>(
  keys: ReadonlyMap<string, T>,
  keyId: string,
  label: string
): T {
  const key = keys.get(keyId);
  if (key === undefined) {
    throw new Error(`${label} ${keyId} was not found`);
  }
  return key;
}

function createSmx1TamperFixture() {
  const aliceIdentity = generateIdentityKeyPair();
  const bobIdentity = generateIdentityKeyPair();
  const bobSigning = generateEd25519KeyPair();
  const bobSpk = generateSignedPrekey(bobSigning.secretKey, 'spk-live');
  const bobOtherSpk = generateSignedPrekey(
    bobSigning.secretKey,
    'spk-other'
  );
  const bobOpk = generateOneTimePrekey('opk-live');
  const bobOtherOpk = generateOneTimePrekey('opk-other');
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
    localIdentity: aliceIdentity,
    recipientBundle
  });
  const envelope = encryptMessage(alice, 'first contact');
  expect(envelope.kind).toBe('smx1');

  return {
    aliceIdentity,
    bobIdentity,
    envelope,
    signedPrekeys: new Map<string, LocalSignedPrekey>([
      [bobSpk.keyId, bobSpk],
      [bobOtherSpk.keyId, bobOtherSpk]
    ]),
    oneTimePrekeys: new Map<string, LocalOneTimePrekey>([
      [bobOpk.keyId, bobOpk],
      [bobOtherOpk.keyId, bobOtherOpk]
    ])
  };
}

function tamperSmx1Field(
  frameBytes: Uint8Array,
  field:
    | 'senderEphemeralPublicKey'
    | 'signedPrekeyId'
    | 'oneTimePrekeyId'
    | 'nonce'
): Uint8Array {
  const parsed = parseSmx1Envelope(frameBytes);
  const senderEphemeralPublicKey = parsed.senderEphemeralPublicKey.slice();
  const nonce = parsed.nonce.slice();
  let signedPrekeyId = parsed.signedPrekeyId;
  let oneTimePrekeyId = parsed.oneTimePrekeyId;

  switch (field) {
    case 'senderEphemeralPublicKey':
      flipFirstByte(senderEphemeralPublicKey);
      break;
    case 'signedPrekeyId':
      signedPrekeyId = 'spk-other';
      break;
    case 'oneTimePrekeyId':
      oneTimePrekeyId = 'opk-other';
      break;
    case 'nonce':
      flipFirstByte(nonce);
      break;
  }

  return encodeSmx1Envelope({
    senderEphemeralPublicKey,
    signedPrekeyId,
    oneTimePrekeyId,
    nonce,
    ciphertext: parsed.ciphertext
  });
}

function flipFirstByte(bytes: Uint8Array): void {
  if (bytes.length === 0) {
    throw new Error('cannot tamper an empty byte array');
  }
  bytes[0] = (bytes[0] ?? 0) ^ 0x01;
}

describe('SMX1 first-contact frame authentication', () => {
  for (const field of [
    'senderEphemeralPublicKey',
    'signedPrekeyId',
    'oneTimePrekeyId',
    'nonce'
  ] as const) {
    it(`rejects SMX1 ${field} tampering`, () => {
      const fixture = createSmx1TamperFixture();
      const tamperedFrame = tamperSmx1Field(fixture.envelope.frameBytes, field);
      const receiver = initReceiverSession({
        localIdentity: fixture.bobIdentity,
        peerIdentityPublicKey: fixture.aliceIdentity.publicKey,
        envelope: tamperedFrame,
        signedPrekeyLookup: (keyId) =>
          lookupOrThrow(fixture.signedPrekeys, keyId, 'SPK'),
        oneTimePrekeyLookup: (keyId) => fixture.oneTimePrekeys.get(keyId)
      });
      const receivingChainKeyBefore = receiver.session.receivingChainKey?.slice();

      expect(() => decryptMessage(receiver.session, tamperedFrame)).toThrow();
      expect(receiver.session.receivingMessageNumber).toBe(0);
      expect(receiver.session.receivingChainKey).toEqual(
        receivingChainKeyBefore
      );
    });
  }

  it('does not burn an unrelated valid OPK when a tampered OPK id fails decryption', () => {
    const fixture = createSmx1TamperFixture();
    const tamperedFrame = tamperSmx1Field(
      fixture.envelope.frameBytes,
      'oneTimePrekeyId'
    );
    const availableOpks = new Map(fixture.oneTimePrekeys);
    const consumedOpks = new Set<string>();

    const decryptAndConsumeAfterSuccess = () => {
      const receiver = initReceiverSession({
        localIdentity: fixture.bobIdentity,
        peerIdentityPublicKey: fixture.aliceIdentity.publicKey,
        envelope: tamperedFrame,
        signedPrekeyLookup: (keyId) =>
          lookupOrThrow(fixture.signedPrekeys, keyId, 'SPK'),
        oneTimePrekeyLookup: (keyId) => availableOpks.get(keyId)
      });
      const plaintext = decryptMessage(receiver.session, tamperedFrame);
      const opkId = receiver.parsedEnvelope.oneTimePrekeyId;
      if (opkId !== undefined) {
        availableOpks.delete(opkId);
        consumedOpks.add(opkId);
      }
      return plaintext;
    };

    expect(decryptAndConsumeAfterSuccess).toThrow();
    expect(availableOpks.has('opk-other')).toBe(true);
    expect(consumedOpks.has('opk-other')).toBe(false);
  });
});
