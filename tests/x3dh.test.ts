import { describe, expect, it } from 'vitest';

import {
  bytesToUtf8,
  decryptMessage,
  deriveX3dhReceiverSecret,
  deriveX3dhSenderSecret,
  ed25519Sign,
  encryptMessage,
  generateEd25519KeyPair,
  generateIdentityKeyPair,
  generateOneTimePrekey,
  generateSignedPrekey,
  generateX25519KeyPair,
  initReceiverSession,
  initSenderSession,
  iosPlanX3dhKdfParameters
} from '../src/index.js';

describe('X3DH derivation helpers', () => {
  it('derive matching sender and receiver secrets when explicit KDF parameters are supplied', () => {
    const aliceIdentity = generateX25519KeyPair();
    const aliceEphemeral = generateX25519KeyPair();
    const bobIdentity = generateX25519KeyPair();
    const bobSigning = generateEd25519KeyPair();
    const bobSpk = generateX25519KeyPair();
    const bobOpk = generateX25519KeyPair();
    const spkSignature = ed25519Sign(bobSpk.publicKey, bobSigning.secretKey);
    const kdf = iosPlanX3dhKdfParameters();

    const senderSecret = deriveX3dhSenderSecret({
      senderIdentitySecretKey: aliceIdentity.secretKey,
      senderEphemeralSecretKey: aliceEphemeral.secretKey,
      recipientBundle: {
        identityAgreementKey: bobIdentity.publicKey,
        identitySigningKey: bobSigning.publicKey,
        signedPrekey: {
          keyId: 'spk-fixture',
          publicKey: bobSpk.publicKey,
          signature: spkSignature
        },
        oneTimePrekey: {
          keyId: 'opk-fixture',
          publicKey: bobOpk.publicKey
        }
      },
      kdf
    });

    const receiverSecret = deriveX3dhReceiverSecret({
      receiverIdentitySecretKey: bobIdentity.secretKey,
      senderIdentityPublicKey: aliceIdentity.publicKey,
      senderEphemeralPublicKey: aliceEphemeral.publicKey,
      receiverSignedPrekey: {
        keyId: 'spk-fixture',
        publicKey: bobSpk.publicKey,
        secretKey: bobSpk.secretKey,
        signature: spkSignature
      },
      receiverOneTimePrekey: {
        keyId: 'opk-fixture',
        publicKey: bobOpk.publicKey,
        secretKey: bobOpk.secretKey
      },
      kdf
    });

    expect(senderSecret).toEqual(receiverSecret);
  });

  it('bootstraps a sender and receiver session through an SMX1 first message', () => {
    const aliceIdentity = generateIdentityKeyPair();
    const bobIdentity = generateIdentityKeyPair();
    const bobSigning = generateEd25519KeyPair();
    const bobSpk = generateSignedPrekey(bobSigning.secretKey, 'spk-live');
    const bobOpk = generateOneTimePrekey('opk-live');

    const senderSession = initSenderSession({
      myIdentity: aliceIdentity,
      recipientBundle: {
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
      }
    });
    const first = encryptMessage(senderSession, 'hello from first contact');

    expect(first.kind).toBe('smx1');
    expect(senderSession.pendingPrekey).toBeUndefined();

    const receiverInit = initReceiverSession({
      myIdentity: bobIdentity,
      senderIdentityPublicKey: aliceIdentity.publicKey,
      envelope: first,
      signedPrekeyLookup: (keyId) => {
        expect(keyId).toBe('spk-live');
        return bobSpk;
      },
      oneTimePrekeyLookup: (keyId) => {
        expect(keyId).toBe('opk-live');
        return bobOpk;
      }
    });

    expect(bytesToUtf8(decryptMessage(receiverInit.session, first))).toBe(
      'hello from first contact'
    );
  });

  it('rejects SMX1 receiver setup when the required one-time prekey is unavailable', () => {
    const aliceIdentity = generateIdentityKeyPair();
    const bobIdentity = generateIdentityKeyPair();
    const bobSigning = generateEd25519KeyPair();
    const bobSpk = generateSignedPrekey(bobSigning.secretKey, 'spk-live');
    const bobOpk = generateOneTimePrekey('opk-live');
    const senderSession = initSenderSession({
      myIdentity: aliceIdentity,
      recipientBundle: {
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
      }
    });
    const first = encryptMessage(
      senderSession,
      'missing OPK should fail before decrypt'
    );

    expect(() =>
      initReceiverSession({
        myIdentity: bobIdentity,
        senderIdentityPublicKey: aliceIdentity.publicKey,
        envelope: first,
        signedPrekeyLookup: () => bobSpk
      })
    ).toThrow('SMX1 one-time prekey was not found');
  });
});
