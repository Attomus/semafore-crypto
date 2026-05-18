import { concatBytes, utf8ToBytes } from './bytes.js';
import { ed25519Verify, hkdfSha256, x25519SharedSecret } from './primitives.js';

export const X3DH_INFO_IOS_PLAN = 'SemaFore-X3DH-v1';
export const X3DH_SALT_ANDROID_PLAN = 'SemaForeX3DHv1';

export interface IdentityKeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export interface SignedPrekey {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
  readonly signature: Uint8Array;
}

export interface LocalSignedPrekey extends SignedPrekey {
  readonly secretKey: Uint8Array;
}

export interface OneTimePrekey {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}

export interface LocalOneTimePrekey extends OneTimePrekey {
  readonly secretKey: Uint8Array;
}

export interface KeyBundle {
  readonly identityAgreementKey: Uint8Array;
  readonly identitySigningKey: Uint8Array;
  readonly signedPrekey: SignedPrekey;
  readonly oneTimePrekey?: OneTimePrekey;
}

export interface X3dhKdfParameters {
  readonly salt?: Uint8Array;
  readonly info?: Uint8Array;
}

export interface X3dhSenderInput {
  readonly senderIdentitySecretKey: Uint8Array;
  readonly senderEphemeralSecretKey: Uint8Array;
  readonly recipientBundle: KeyBundle;
  readonly kdf: X3dhKdfParameters;
}

export interface X3dhReceiverInput {
  readonly receiverIdentitySecretKey: Uint8Array;
  readonly senderIdentityPublicKey: Uint8Array;
  readonly senderEphemeralPublicKey: Uint8Array;
  readonly receiverSignedPrekey: LocalSignedPrekey;
  readonly receiverOneTimePrekey?: LocalOneTimePrekey;
  readonly kdf: X3dhKdfParameters;
}

export function verifySignedPrekey(identityPublicKey: Uint8Array, signedPrekey: SignedPrekey): boolean {
  return ed25519Verify(signedPrekey.signature, signedPrekey.publicKey, identityPublicKey);
}

export function deriveX3dhSenderSecret(input: X3dhSenderInput): Uint8Array {
  if (!verifySignedPrekey(input.recipientBundle.identitySigningKey, input.recipientBundle.signedPrekey)) {
    throw new Error('recipient signed prekey signature is invalid');
  }
  const dh1 = x25519SharedSecret(input.senderIdentitySecretKey, input.recipientBundle.signedPrekey.publicKey);
  const dh2 = x25519SharedSecret(input.senderEphemeralSecretKey, input.recipientBundle.identityAgreementKey);
  const dh3 = x25519SharedSecret(input.senderEphemeralSecretKey, input.recipientBundle.signedPrekey.publicKey);
  const dh4 =
    input.recipientBundle.oneTimePrekey === undefined
      ? new Uint8Array()
      : x25519SharedSecret(input.senderEphemeralSecretKey, input.recipientBundle.oneTimePrekey.publicKey);
  return hkdfSha256(concatBytes([dh1, dh2, dh3, dh4]), input.kdf.salt, input.kdf.info, 32);
}

export function deriveX3dhReceiverSecret(input: X3dhReceiverInput): Uint8Array {
  const dh1 = x25519SharedSecret(input.receiverSignedPrekey.secretKey, input.senderIdentityPublicKey);
  const dh2 = x25519SharedSecret(input.receiverIdentitySecretKey, input.senderEphemeralPublicKey);
  const dh3 = x25519SharedSecret(input.receiverSignedPrekey.secretKey, input.senderEphemeralPublicKey);
  const dh4 =
    input.receiverOneTimePrekey === undefined
      ? new Uint8Array()
      : x25519SharedSecret(input.receiverOneTimePrekey.secretKey, input.senderEphemeralPublicKey);
  return hkdfSha256(concatBytes([dh1, dh2, dh3, dh4]), input.kdf.salt, input.kdf.info, 32);
}

export function iosPlanX3dhKdfParameters(): X3dhKdfParameters {
  return {
    salt: new Uint8Array(32),
    info: utf8ToBytes(X3DH_INFO_IOS_PLAN)
  };
}

export function androidPlanX3dhKdfParameters(): X3dhKdfParameters {
  return {
    salt: utf8ToBytes(X3DH_SALT_ANDROID_PLAN),
    info: new Uint8Array()
  };
}
