import { describe, expect, it } from 'vitest';

import {
  deriveX3dhReceiverSecret,
  deriveX3dhSenderSecret,
  ed25519Sign,
  generateEd25519KeyPair,
  generateX25519KeyPair,
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
});
