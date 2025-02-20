import { NitroModules } from 'react-native-nitro-modules'

import type { Secp256k1 } from './specs/secp256k1.nitro'

export * from './specs/secp256k1.nitro'

/**
 * The Hybrid Test Object in C++
 */
export const HybridTestObjectCpp =
  NitroModules.createHybridObject<Secp256k1>('Secp256k1')
