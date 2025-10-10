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

  broadcast.update(b4a.alloc(32, 1), [keyPair.publicKey])

  t.alike(await broadcast.get(0), { id: 0, entropy: null })
  t.alike(await broadcast.get(1), { id: 1, entropy: b4a.alloc(32, 1) })
  t.alike(await broadcast.get(2, { wait: false }), null)
  t.alike(await broadcast.get(-1), { id: 1, entropy: b4a.alloc(32, 1) })
})

test('genesis', async (t) => {
  const core = new Hypercore(await t.tmp())
  await core.ready()

  const keyPair = crypto.keyPair()

  const broadcast = new Broadcast(core, { keyPair, genesis: b4a.alloc(32) })
  await broadcast.ready()

  broadcast.update(b4a.alloc(32, 1), [keyPair.publicKey])

  t.alike(await broadcast.get(0), { id: 0, entropy: b4a.alloc(32) })
  t.alike(await broadcast.get(1), { id: 1, entropy: b4a.alloc(32, 1) })
  t.alike(await broadcast.get(2, { wait: false }), null)
})

test('replication', async (t) => {
  const local = new Hypercore(await t.tmp())
  await local.ready()

  const remote = new Hypercore(await t.tmp(), { key: local.key })
  await remote.ready()

  const a = crypto.keyPair()
  const b = crypto.keyPair()

  const broadcaster = new Broadcast(local, {
    keyPair: a,
    genesis: b4a.alloc(32)
  })
  await broadcaster.ready()

  const receiver = new Broadcast(remote, {
    keyPair: b,
    genesis: b4a.alloc(32)
  })
  await receiver.ready()

  broadcaster.update(b4a.alloc(32, 1), [a.publicKey, b.publicKey])
  broadcaster.update(b4a.alloc(32, 2), [a.publicKey, b.publicKey])

  replicate(local, remote, t)

  t.alike(await receiver.get(0), { id: 0, entropy: b4a.alloc(32) })
  t.alike(await receiver.get(1), { id: 1, entropy: b4a.alloc(32, 1) })
  t.alike(await receiver.get(2), { id: 2, entropy: b4a.alloc(32, 2) })

  // remove b from receivers
  broadcaster.update(b4a.alloc(32, 3), [a.publicKey])

  await t.exception(receiver.get(3), /Broadcast decryption failed/)
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
