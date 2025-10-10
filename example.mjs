import Corestore from 'corestore'
import b4a from 'b4a'
import crypto from 'hypercore-crypto'
import Broadcast from './index.js'

const keyPair1 = crypto.keyPair()
const keyPair2 = crypto.keyPair()
const genesis = b4a.alloc(32, 1)

const local = new Corestore('./local')
const remote = new Corestore('./remote')

// set up the writer
const broadcasterCore = local.get({ name: 'broadcast' })
const broadcaster = new Broadcast(broadcasterCore, { genesis, keyPair: keyPair1 })
await broadcaster.ready()

const writer = local.get({ name: 'data' })
await writer.ready()
await writer.setEncryption(broadcaster.createEncryptionProvider())

// set up the reader
const receiverCore = remote.get({ key: broadcaster.core.key })
const receiver = new Broadcast(receiverCore, { genesis, keyPair: keyPair2 })
await receiver.ready()

const reader = remote.get({ key: writer.key })
await reader.ready()
await reader.setEncryption(receiver.createEncryptionProvider())

replicate(local, remote)

// write some data
await writer.append('block 1')
await writer.append('block 2')

// update encryption key
await broadcaster.update(b4a.alloc(32, 2), [keyPair1.publicKey, keyPair2.publicKey])

// write some more data
await writer.append('block 3')
await writer.append('block 4')

// update the encryption key and remove keyPair 2
await broadcaster.update(b4a.alloc(32, 3), [keyPair1.publicKey])

await writer.append('block 5')

console.log((await reader.get(0, { raw: true })))
console.log((await reader.get(1, { raw: true })))
console.log((await reader.get(2, { raw: true })))
console.log((await reader.get(3, { raw: true })))

// this will throw
console.log((await reader.get(4)))

function replicate(a, b) {
  let destroyed = false

  const s1 = a.replicate(true)
  const s2 = b.replicate(false)

  s1.pipe(s2).pipe(s1)

  return destroy

  function destroy() {
    if (destroyed) return
    destroyed = true

    const end = Promise.all([
      new Promise((resolve) => s1.on('close', resolve)),
      new Promise((resolve) => s2.on('close', resolve))
    ])

    s1.destroy()

    return end
  }
}
