const Hypercore = require('hypercore')
const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const test = require('brittle')

const Broadcast = require('../')

test('simple', async (t) => {
  const core = new Hypercore(await t.tmp())
  await core.ready()

  const keyPair = crypto.keyPair()

  const broadcast = new Broadcast(core, { keyPair })
  await broadcast.ready()

  await broadcast.update(b4a.alloc(32, 1), [keyPair.publicKey])

  t.alike(await broadcast.get(0), { id: 0, encryptionKey: null })
  t.alike(await broadcast.get(1), { id: 1, encryptionKey: b4a.alloc(32, 1) })
  t.alike(await broadcast.get(3, { wait: false }), null)
  t.alike(await broadcast.get(-1), { id: 1, encryptionKey: b4a.alloc(32, 1) })
})

test('replication', async (t) => {
  const local = new Hypercore(await t.tmp())
  await local.ready()

  const remote = new Hypercore(await t.tmp(), { key: local.key })
  await remote.ready()

  const a = crypto.keyPair()
  const b = crypto.keyPair()

  const broadcaster = new Broadcast(local, { keyPair: a })
  await broadcaster.ready()

  const receiver = new Broadcast(remote, { keyPair: b })
  await receiver.ready()

  await broadcaster.update(b4a.alloc(32, 1), [a.publicKey, b.publicKey])
  await broadcaster.update(b4a.alloc(32, 2), [a.publicKey, b.publicKey])

  replicate(local, remote, t)

  t.alike(await receiver.get(0), { id: 0, encryptionKey: null })
  t.alike(await receiver.get(1), { id: 1, encryptionKey: b4a.alloc(32, 1) })
  t.alike(await receiver.get(3), { id: 3, encryptionKey: b4a.alloc(32, 2) })

  // remove b from receivers
  await broadcaster.update(b4a.alloc(32, 3), [a.publicKey])

  await t.exception(receiver.get(5), /Broadcast decryption failed/)
})

test('bootstrap', async (t) => {
  const local = new Hypercore(await t.tmp())
  await local.ready()

  const remote = new Hypercore(await t.tmp(), { key: local.key })
  await remote.ready()

  const a = crypto.keyPair()
  const b = crypto.keyPair()

  const broadcaster = new Broadcast(local, { keyPair: a })
  await broadcaster.ready()

  await broadcaster.update(b4a.alloc(32, 1), [a.publicKey])
  await broadcaster.update(b4a.alloc(32, 2), [a.publicKey])
  await broadcaster.update(b4a.alloc(32, 3), [a.publicKey])
  await broadcaster.update(b4a.alloc(32, 4), [a.publicKey])
  await broadcaster.update(b4a.alloc(32, 5), [a.publicKey])

  replicate(local, remote, t)

  const receiver = new Broadcast(remote, {
    keyPair: b,
    bootstrap: {
      encryptionKey: b4a.alloc(32, 5),
      id: 9
    }
  })

  await receiver.ready()

  t.alike(await receiver.get(1), { id: 1, encryptionKey: b4a.alloc(32, 1) })

  await broadcaster.update(b4a.alloc(32, 6), [a.publicKey, b.publicKey])

  t.alike(await receiver.get(11), { id: 11, encryptionKey: b4a.alloc(32, 6) })
})

test('removed and readded', async (t) => {
  const local = new Hypercore(await t.tmp())
  await local.ready()

  const remote = new Hypercore(await t.tmp(), { key: local.key })
  await remote.ready()

  const a = crypto.keyPair()
  const b = crypto.keyPair()

  const broadcaster = new Broadcast(local, { keyPair: a })
  await broadcaster.ready()

  await broadcaster.update(b4a.alloc(32, 1), [a.publicKey, b.publicKey])
  await broadcaster.update(b4a.alloc(32, 3), [a.publicKey])
  await broadcaster.update(b4a.alloc(32, 5), [a.publicKey, b.publicKey])

  replicate(local, remote, t)

  const receiver = new Broadcast(remote, { keyPair: b })
  await receiver.ready()

  t.alike(await receiver.get(0), { id: 0, encryptionKey: null })
  t.alike(await receiver.get(1), { id: 1, encryptionKey: b4a.alloc(32, 1) })
  t.alike(await receiver.get(3), { id: 3, encryptionKey: b4a.alloc(32, 3) })
  t.alike(await receiver.get(5), { id: 5, encryptionKey: b4a.alloc(32, 5) })
})

test('access previous keys', async (t) => {
  const local = new Hypercore(await t.tmp())
  await local.ready()

  const remote = new Hypercore(await t.tmp(), { key: local.key })
  await remote.ready()

  const a = crypto.keyPair()
  const b = crypto.keyPair()

  const broadcaster = new Broadcast(local, { keyPair: a })
  await broadcaster.ready()

  await broadcaster.update(b4a.alloc(32, 1), [a.publicKey])
  await broadcaster.update(b4a.alloc(32, 3), [a.publicKey])

  replicate(local, remote, t)

  const receiver = new Broadcast(remote, { keyPair: b })
  await receiver.ready()

  await t.exception(receiver.get(1))
  await t.exception(receiver.get(3))

  const update = new Promise((resolve) => receiver.on('update', resolve))

  await broadcaster.update(b4a.alloc(32, 5), [a.publicKey, b.publicKey])

  t.alike(await update, 5)

  t.alike(await receiver.get(1), { id: 1, encryptionKey: b4a.alloc(32, 1) })
  t.alike(await receiver.get(3), { id: 3, encryptionKey: b4a.alloc(32, 3) })
  t.alike(await receiver.get(5), { id: 5, encryptionKey: b4a.alloc(32, 5) })
})

function replicate(a, b, t) {
  let destroyed = false

  const s1 = a.replicate(true)
  const s2 = b.replicate(false)

  s1.pipe(s2).pipe(s1)

  t.teardown(destroy)

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
