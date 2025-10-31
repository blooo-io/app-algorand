/** ******************************************************************************
 *  (c) 2018 - 2022 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

// @ts-ignore
import Zemu, { DEFAULT_START_OPTIONS, ButtonKind, isTouchDevice } from '@zondax/zemu'
// @ts-ignore
import { AlgorandApp } from '@zondax/ledger-algorand'
import { APP_SEED, models } from './common'
import { encode } from '@msgpack/msgpack'

// @ts-ignore
import ed25519 from 'ed25519-supercop'
import { expect, test, describe, beforeEach } from 'vitest'
import { errorCodeToString, LedgerError } from '@zondax/ledger-algorand/dist/common'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

const accountId = 0

beforeEach(() => {
  // This is handled by the vitest.config.ts file
})

// Helper function to decode Algorand address to 32 bytes
function decodeAddress(address: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const decode = (str: string) => {
    let bits = 0
    let value = 0
    let output = []
    
    for (let i = 0; i < str.length; i++) {
      const char = str[i]
      const index = alphabet.indexOf(char)
      
      if (index === -1) continue
      
      value = (value << 5) | index
      bits += 5
      
      if (bits >= 8) {
        output.push((value >> (bits - 8)) & 0xFF)
        bits -= 8
      }
    }
    
    return Buffer.from(output)
  }
  
  const decoded = decode(address)
  // Remove the last 4 bytes (checksum)
  return decoded.slice(0, 32)
}

// Create the aprv transaction from the spec
const aprvTransaction = {
  apid: 1005,
  aprv: 3, // Reject if application 1005 version is 3 or more
  fee: 1000,
  fv: 931,
  gh: Buffer.from('t9fO3Zr2fsmd8Dg+0HkTKwX9dkf73CViBarLDH2hLtw=', 'base64'),
  lv: 1931,
  snd: decodeAddress('ALICE7Y2JOFGG2VGUC64VINB75PI56O6M2XW233KG2I3AIYJFUD4QMYTJM'),
  type: 'appl'
}

const txAprvBlob = Buffer.from(encode(aprvTransaction))

describe('Application Reject Version', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign transaction with aprv field', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AlgorandApp(sim.getTransport())

      const responseAddr = await app.getAddressAndPubKey(accountId)
      const pubKey = responseAddr.publicKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(accountId, txAprvBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_aprv`)

      const signatureResponse = await signatureRequest

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual(errorCodeToString(LedgerError.NoErrors))

      // Now verify the signature
      const prehash = Buffer.concat([Buffer.from('TX'), txAprvBlob])
      const valid = ed25519.verify(signatureResponse.signature, prehash, pubKey)
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

