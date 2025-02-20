import { type HybridObject } from 'react-native-nitro-modules'

export interface Secp256k1
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  /*
   * Keys
   */
  privateKeyIsValid(privateKey: ArrayBuffer): boolean
  privateKeyToPublicKey(
    privateKey: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer
  publicKeyIsValid(publicKey: ArrayBuffer, compressed: boolean): boolean
  publicKeyConvert(publicKey: ArrayBuffer, compressed: boolean): ArrayBuffer
  xOnlyIsValid(xOnly: ArrayBuffer): boolean

  /*
   * Tweaks
   */
  privateKeyTweakAdd(privateKey: ArrayBuffer, tweak: ArrayBuffer): ArrayBuffer
  privateKeyTweakSubtract(
    privateKey: ArrayBuffer,
    tweak: ArrayBuffer
  ): ArrayBuffer
  privateKeyTweakNegate(privateKey: ArrayBuffer): ArrayBuffer
  publicKeyTweakAddPoint(
    publicKey: ArrayBuffer,
    tweakPoint: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer
  publicKeyTweakAddScalar(
    publicKey: ArrayBuffer,
    tweak: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer
  publicKeyTweakMultiply(
    publicKey: ArrayBuffer,
    tweak: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer
  xOnlyTweakAdd(
    xOnly: ArrayBuffer,
    tweak: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer

  /*
   * ECDSA
   */
  ecdsaSignHash(
    hash: ArrayBuffer,
    privateKey: ArrayBuffer,
    der: boolean,
    recovery: boolean,
    extraEntropy?: ArrayBuffer
  ): ArrayBuffer
  ecdsaVerifyHash(
    signature: ArrayBuffer,
    hash: ArrayBuffer,
    publicKey: ArrayBuffer
  ): boolean

  /*
   * Schnorr
   */
  schnorrSign(
    message: ArrayBuffer,
    privateKey: ArrayBuffer,
    extraEntropy?: ArrayBuffer
  ): ArrayBuffer
  schnorrVerify(
    signature: ArrayBuffer,
    message: ArrayBuffer,
    xOnly: ArrayBuffer
  ): boolean
}
