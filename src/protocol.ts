import { bytesToHex, concatBytes, equalBytes } from './bytes.js';
import {
  deriveDrV1BootstrapKeys,
  deriveDrV1MessageKeys,
  deriveDrV1RatchetKeys,
  encodeDrV1Header,
  parseDrV1Header,
  SMD1_HEADER_LENGTH,
  type DrV1Header
} from './dr-v1.js';
import {
  aes256GcmDecrypt,
  aes256GcmEncryptWithNonce,
  ed25519Sign,
  generateX25519KeyPair,
  type KeyPair
} from './primitives.js';
import { randomBytes } from './random.js';
import {
  encodeSmx1Envelope,
  parseSmx1Envelope,
  SMX1_MAGIC,
  type ParsedSmx1Envelope
} from './smx1.js';
import {
  deriveX3dhReceiverSecret,
  deriveX3dhSenderSecret,
  iosPlanX3dhKdfParameters,
  type IdentityKeyPair,
  type KeyBundle,
  type LocalOneTimePrekey,
  type LocalSignedPrekey,
  type OneTimePrekey,
  type SignedPrekey,
  type X3dhKdfParameters
} from './x3dh.js';

export type EnvelopeKind = 'smx1' | 'smd1';

export interface Envelope {
  readonly kind: EnvelopeKind;
  readonly headerBytes: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly frameBytes: Uint8Array;
}

export interface SessionState {
  rootKey: Uint8Array;
  localRatchetKeyPair: KeyPair;
  remoteRatchetPublicKey?: Uint8Array;
  sendingChainKey?: Uint8Array;
  receivingChainKey?: Uint8Array;
  sendingMessageNumber: number;
  receivingMessageNumber: number;
  previousSendingChainLength: number;
  skippedMessageKeys: SkippedMessageKey[];
  pendingPrekey?: PendingPrekeyEnvelope;
  maxSkippedMessageKeys: number;
}

export interface SkippedMessageKey {
  readonly ratchetPublicKeyHex: string;
  readonly messageNumber: number;
  readonly messageKey: Uint8Array;
}

export interface PendingPrekeyEnvelope {
  readonly signedPrekeyId: string;
  readonly oneTimePrekeyId?: string;
}

export interface InitSenderSessionInput {
  readonly myIdentity: IdentityKeyPair;
  readonly recipientBundle: KeyBundle;
  readonly ephemeralKeyPair?: KeyPair;
  readonly kdf?: X3dhKdfParameters;
  readonly maxSkippedMessageKeys?: number;
}

export interface InitReceiverSessionInput {
  readonly myIdentity: IdentityKeyPair;
  readonly senderIdentityPublicKey: Uint8Array;
  readonly envelope: Uint8Array | Envelope;
  readonly signedPrekeyLookup: (keyId: string) => LocalSignedPrekey;
  readonly oneTimePrekeyLookup?: (
    keyId: string
  ) => LocalOneTimePrekey | undefined;
  readonly kdf?: X3dhKdfParameters;
  readonly localRatchetKeyPair?: KeyPair;
  readonly maxSkippedMessageKeys?: number;
}

export interface InitReceiverSessionResult {
  readonly session: SessionState;
  readonly parsedEnvelope: ParsedSmx1Envelope;
}

export function generateIdentityKeyPair(): IdentityKeyPair {
  return generateX25519KeyPair();
}

export function generateSignedPrekey(
  identitySigningSecretKey: Uint8Array,
  keyId: string
): LocalSignedPrekey {
  const keyPair = generateX25519KeyPair();
  return {
    keyId,
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
    signature: ed25519Sign(keyPair.publicKey, identitySigningSecretKey)
  };
}

export function generateOneTimePrekey(keyId: string): LocalOneTimePrekey {
  const keyPair = generateX25519KeyPair();
  return {
    keyId,
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey
  };
}

export function publicSignedPrekey(prekey: LocalSignedPrekey): SignedPrekey {
  return {
    keyId: prekey.keyId,
    publicKey: prekey.publicKey,
    signature: prekey.signature
  };
}

export function publicOneTimePrekey(prekey: LocalOneTimePrekey): OneTimePrekey {
  return {
    keyId: prekey.keyId,
    publicKey: prekey.publicKey
  };
}

export function initSenderSession(input: InitSenderSessionInput): SessionState {
  const ephemeralKeyPair = input.ephemeralKeyPair ?? generateX25519KeyPair();
  const x3dhSecret = deriveX3dhSenderSecret({
    senderIdentitySecretKey: input.myIdentity.secretKey,
    senderEphemeralSecretKey: ephemeralKeyPair.secretKey,
    recipientBundle: input.recipientBundle,
    kdf: input.kdf ?? iosPlanX3dhKdfParameters()
  });
  const bootstrap = deriveDrV1BootstrapKeys(x3dhSecret);

  return {
    rootKey: bootstrap.rootKey,
    localRatchetKeyPair: ephemeralKeyPair,
    remoteRatchetPublicKey: input.recipientBundle.signedPrekey.publicKey,
    sendingChainKey: bootstrap.chainKey,
    sendingMessageNumber: 0,
    receivingMessageNumber: 0,
    previousSendingChainLength: 0,
    skippedMessageKeys: [],
    pendingPrekey: {
      signedPrekeyId: input.recipientBundle.signedPrekey.keyId,
      oneTimePrekeyId: input.recipientBundle.oneTimePrekey?.keyId
    },
    maxSkippedMessageKeys: input.maxSkippedMessageKeys ?? 64
  };
}

export function initReceiverSession(
  input: InitReceiverSessionInput
): InitReceiverSessionResult {
  const parsedEnvelope = parseSmx1Envelope(envelopeBytes(input.envelope));
  const signedPrekey = input.signedPrekeyLookup(parsedEnvelope.signedPrekeyId);
  const oneTimePrekey =
    parsedEnvelope.oneTimePrekeyId === undefined
      ? undefined
      : input.oneTimePrekeyLookup?.(parsedEnvelope.oneTimePrekeyId);

  if (
    parsedEnvelope.oneTimePrekeyId !== undefined &&
    oneTimePrekey === undefined
  ) {
    throw new Error('SMX1 one-time prekey was not found');
  }

  const x3dhSecret = deriveX3dhReceiverSecret({
    receiverIdentitySecretKey: input.myIdentity.secretKey,
    senderIdentityPublicKey: input.senderIdentityPublicKey,
    senderEphemeralPublicKey: parsedEnvelope.senderEphemeralPublicKey,
    receiverSignedPrekey: signedPrekey,
    receiverOneTimePrekey: oneTimePrekey,
    kdf: input.kdf ?? iosPlanX3dhKdfParameters()
  });
  const bootstrap = deriveDrV1BootstrapKeys(x3dhSecret);

  return {
    parsedEnvelope,
    session: {
      rootKey: bootstrap.rootKey,
      localRatchetKeyPair: input.localRatchetKeyPair ?? generateX25519KeyPair(),
      remoteRatchetPublicKey: parsedEnvelope.senderEphemeralPublicKey,
      receivingChainKey: bootstrap.chainKey,
      sendingMessageNumber: 0,
      receivingMessageNumber: 0,
      previousSendingChainLength: 0,
      skippedMessageKeys: [],
      maxSkippedMessageKeys: input.maxSkippedMessageKeys ?? 64
    }
  };
}

export function encryptMessage(
  session: SessionState,
  plaintext: Uint8Array | string
): Envelope {
  const plaintextBytes =
    typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;
  const chainKey = ensureSendingChain(session);
  const keys = deriveDrV1MessageKeys(chainKey);
  const nonce = randomBytes(12);
  session.sendingChainKey = keys.nextChainKey;

  const pendingPrekey = session.pendingPrekey;
  if (pendingPrekey !== undefined) {
    const frameBytes = encodeSmx1Envelope({
      senderEphemeralPublicKey: session.localRatchetKeyPair.publicKey,
      signedPrekeyId: pendingPrekey.signedPrekeyId,
      oneTimePrekeyId: pendingPrekey.oneTimePrekeyId,
      nonce,
      ciphertext: aes256GcmEncryptWithNonce(
        keys.messageKey,
        nonce,
        plaintextBytes
      )
    });
    const parsed = parseSmx1Envelope(frameBytes);
    session.pendingPrekey = undefined;
    session.sendingMessageNumber += 1;
    return {
      kind: 'smx1',
      headerBytes: parsed.headerBytes,
      ciphertext: parsed.ciphertext,
      frameBytes
    };
  }

  const header = encodeDrV1Header({
    ratchetPublicKey: session.localRatchetKeyPair.publicKey,
    previousChainLength: session.previousSendingChainLength,
    messageNumber: session.sendingMessageNumber,
    nonce
  });
  const ciphertext = aes256GcmEncryptWithNonce(
    keys.messageKey,
    nonce,
    plaintextBytes,
    header
  );
  session.sendingMessageNumber += 1;

  return {
    kind: 'smd1',
    headerBytes: header,
    ciphertext,
    frameBytes: concatBytes([header, ciphertext])
  };
}

export function decryptMessage(
  session: SessionState,
  envelope: Uint8Array | Envelope
): Uint8Array {
  const frame = envelopeBytes(envelope);
  if (equalBytes(frame.slice(0, 4), SMX1_MAGIC)) {
    return decryptSmx1(session, parseSmx1Envelope(frame));
  }

  const header = parseDrV1Header(frame);
  const ciphertext = frame.slice(SMD1_HEADER_LENGTH);
  return decryptSmd1(session, header, ciphertext);
}

function decryptSmx1(
  session: SessionState,
  envelope: ParsedSmx1Envelope
): Uint8Array {
  const chainKey = requireReceivingChain(session);
  const keys = deriveDrV1MessageKeys(chainKey);
  const plaintext = aes256GcmDecrypt(
    keys.messageKey,
    envelope.nonce,
    envelope.ciphertext
  );
  session.receivingChainKey = keys.nextChainKey;
  session.receivingMessageNumber += 1;
  return plaintext;
}

function decryptSmd1(
  session: SessionState,
  header: DrV1Header,
  ciphertext: Uint8Array
): Uint8Array {
  const skipped = takeSkippedMessageKey(
    session,
    header.ratchetPublicKey,
    header.messageNumber
  );
  if (skipped !== undefined) {
    return aes256GcmDecrypt(
      skipped,
      header.nonce,
      ciphertext,
      encodeDrV1Header(header)
    );
  }

  if (
    !session.remoteRatchetPublicKey ||
    !equalBytes(header.ratchetPublicKey, session.remoteRatchetPublicKey)
  ) {
    skipMessageKeys(session, header.previousChainLength);
    ratchetToRemoteKey(session, header.ratchetPublicKey);
  }

  skipMessageKeys(session, header.messageNumber);
  const chainKey = requireReceivingChain(session);
  const keys = deriveDrV1MessageKeys(chainKey);
  const plaintext = aes256GcmDecrypt(
    keys.messageKey,
    header.nonce,
    ciphertext,
    encodeDrV1Header(header)
  );
  session.receivingChainKey = keys.nextChainKey;
  session.receivingMessageNumber += 1;
  return plaintext;
}

function ensureSendingChain(session: SessionState): Uint8Array {
  if (session.sendingChainKey !== undefined) {
    return session.sendingChainKey;
  }
  if (session.remoteRatchetPublicKey === undefined) {
    throw new Error(
      'cannot derive sending chain before remote ratchet key is known'
    );
  }
  const sendingKeys = deriveDrV1RatchetKeys(
    session.rootKey,
    session.localRatchetKeyPair.secretKey,
    session.remoteRatchetPublicKey
  );
  session.rootKey = sendingKeys.rootKey;
  session.sendingChainKey = sendingKeys.chainKey;
  session.sendingMessageNumber = 0;
  return sendingKeys.chainKey;
}

function ratchetToRemoteKey(
  session: SessionState,
  remoteRatchetPublicKey: Uint8Array
): void {
  const receivingKeys = deriveDrV1RatchetKeys(
    session.rootKey,
    session.localRatchetKeyPair.secretKey,
    remoteRatchetPublicKey
  );
  session.rootKey = receivingKeys.rootKey;
  session.receivingChainKey = receivingKeys.chainKey;
  session.remoteRatchetPublicKey = remoteRatchetPublicKey;
  session.receivingMessageNumber = 0;

  session.previousSendingChainLength = session.sendingMessageNumber;
  session.localRatchetKeyPair = generateX25519KeyPair();
  const sendingKeys = deriveDrV1RatchetKeys(
    session.rootKey,
    session.localRatchetKeyPair.secretKey,
    remoteRatchetPublicKey
  );
  session.rootKey = sendingKeys.rootKey;
  session.sendingChainKey = sendingKeys.chainKey;
  session.sendingMessageNumber = 0;
}

function skipMessageKeys(
  session: SessionState,
  untilMessageNumber: number
): void {
  if (untilMessageNumber < session.receivingMessageNumber) {
    return;
  }
  if (
    untilMessageNumber - session.receivingMessageNumber >
    session.maxSkippedMessageKeys
  ) {
    throw new Error('too many skipped message keys requested');
  }
  const remoteRatchetPublicKey = session.remoteRatchetPublicKey;
  if (remoteRatchetPublicKey === undefined) {
    return;
  }

  while (session.receivingMessageNumber < untilMessageNumber) {
    const chainKey = requireReceivingChain(session);
    const keys = deriveDrV1MessageKeys(chainKey);
    rememberSkippedMessageKey(
      session,
      remoteRatchetPublicKey,
      session.receivingMessageNumber,
      keys.messageKey
    );
    session.receivingChainKey = keys.nextChainKey;
    session.receivingMessageNumber += 1;
  }
}

function rememberSkippedMessageKey(
  session: SessionState,
  ratchetPublicKey: Uint8Array,
  messageNumber: number,
  messageKey: Uint8Array
): void {
  session.skippedMessageKeys.push({
    ratchetPublicKeyHex: bytesToHex(ratchetPublicKey),
    messageNumber,
    messageKey
  });
  if (session.skippedMessageKeys.length > session.maxSkippedMessageKeys) {
    session.skippedMessageKeys.splice(
      0,
      session.skippedMessageKeys.length - session.maxSkippedMessageKeys
    );
  }
}

function takeSkippedMessageKey(
  session: SessionState,
  ratchetPublicKey: Uint8Array,
  messageNumber: number
): Uint8Array | undefined {
  const ratchetPublicKeyHex = bytesToHex(ratchetPublicKey);
  const index = session.skippedMessageKeys.findIndex(
    (entry) =>
      entry.ratchetPublicKeyHex === ratchetPublicKeyHex &&
      entry.messageNumber === messageNumber
  );
  if (index === -1) {
    return undefined;
  }
  const [entry] = session.skippedMessageKeys.splice(index, 1);
  return entry?.messageKey;
}

function requireReceivingChain(session: SessionState): Uint8Array {
  if (session.receivingChainKey === undefined) {
    throw new Error('receiving chain is not initialised');
  }
  return session.receivingChainKey;
}

function envelopeBytes(envelope: Uint8Array | Envelope): Uint8Array {
  return envelope instanceof Uint8Array ? envelope : envelope.frameBytes;
}
