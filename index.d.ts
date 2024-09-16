/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

export interface IdentityKeys {
  ed25519: string
  curve25519: string
}
export declare class Account {
  constructor()
  identityKeys(): IdentityKeys
  static fromPickle(pickle: string, pickleKey: string): Account
  static fromLibolmPickle(pickle: string, pickleKey: string): Account
  pickle(pickleKey: string): string
  get ed25519Key(): string
  get curve25519Key(): string
  sign(message: string): string
  get maxNumberOfOneTimeKeys(): number
  get oneTimeKeys(): Record<string, string>
  generateOneTimeKeys(count: number): void
  get fallbackKey(): object
  generateFallbackKey(): void
  markKeysAsPublished(): void
  createOutboundSession(identityKey: string, oneTimeKey: string, config: SessionConfig): Session
  createInboundSession(identityKey: string, message: OlmMessage): { session: Session, plaintext: string }
}
export declare class Session {
  pickle(pickleKey: string): string
  static fromPickle(pickle: string, pickleKey: string): Session
  static fromLibolmPickle(pickle: string, pickleKey: string): Session
  get sessionId(): string
  sessionMatches(message: OlmMessage): boolean
  encrypt(plaintext: string): OlmMessage
  decrypt(message: OlmMessage): string
}
export declare class Sas {
  constructor()
  get publicKey(): string
}
export declare class EstablishedSas {
  calculateMac(input: string, info: string): string
  calculateMacInvalidBase64(input: string, info: string): string
  verifyMac(input: string, info: string, tag: string): void
}
export declare class SasBytes {
  get emojiIndices(): Array<number>
  get decimals(): Array<number>
}
export declare class GroupSession {
  constructor(config: SessionConfig)
  get sessionId(): string
  get sessionKey(): string
  get messageIndex(): number
  encrypt(plaintext: string): string
  pickle(pickleKey: string): string
  static fromPickle(pickle: string, pickleKey: string): GroupSession
}
export declare class DecryptedMessage {
  plaintext: string
  messageIndex: number
}
export declare class InboundGroupSession {
  constructor(sessionKey: string, sessionConfig: SessionConfig)
  static import(sessionKey: string, sessionConfig: SessionConfig): InboundGroupSession
  get sessionId(): string
  get firstKnownIndex(): number
  exportAt(index: number): string | null
  decrypt(ciphertext: string): DecryptedMessage
  pickle(pickleKey: Uint8Array): string
  static fromPickle(pickle: string, pickleKey: string): InboundGroupSession
  static fromLibolmPickle(pickle: string, pickleKey: string): InboundGroupSession
}
export declare class SessionConfig {
  /** Get the numeric version of this `SessionConfig`. */
  version(): number
  /**
   * Create a `SessionConfig` for the Olm version 1. This version of Olm will
   * use AES-256 and HMAC with a truncated MAC to encrypt individual
   * messages. The MAC will be truncated to 8 bytes.
   */
  static version1(): SessionConfig
  /**
   * Create a `SessionConfig` for the Olm version 2. This version of Olm will
   * use AES-256 and HMAC to encrypt individual messages. The MAC won't be
   * truncated.
   */
  static version2(): SessionConfig
}
export declare class OlmMessage {
  ciphertext: string
  messageType: number
  constructor(messageType: number, ciphertext: string)
}
