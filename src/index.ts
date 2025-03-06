import { NitroModules } from 'react-native-nitro-modules'

import type { Secp256k1 as _Secp256k1 } from './specs/secp256k1.nitro'

export type ISecp256k1 = _Secp256k1

export const Secp256k1 =
  NitroModules.createHybridObject<ISecp256k1>('Secp256k1')
