import { type HybridObject } from 'react-native-nitro-modules'

export interface Secp256k1
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  privateKeyIsValid(privateKey: ArrayBuffer): boolean
  privateKeyToPublicKey(
    privateKey: ArrayBuffer,
    compressed: boolean
  ): ArrayBuffer
}
