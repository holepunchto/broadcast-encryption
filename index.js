const sodium = require('sodium-universal')
const ReadyResource = require('ready-resource')
const crypto = require('hypercore-crypto')
const c = require('compact-encoding')
const safetyCatch = require('safety-catch')
const b4a = require('b4a')
const rrp = require('resolve-reject-promise')

const schema = require('./spec/broadcast-encryption')

const [DEFAULT_NAMESPACE, GENESIS_ENTROPY, NS_NONCE, NS_KEYPAIR_SEED, NS_SYMMETRIC_NONCE] =
  crypto.namespace('broadcast-encryption', 5)

// ephemeral state
const nonce = b4a.alloc(sodium.crypto_stream_NONCEBYTES)
const hash = nonce.subarray(0, sodium.crypto_generichash_BYTES_MIN)
const secretKey = b4a.alloc(sodium.crypto_box_SECRETKEYBYTES)
const publicKey = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)
const recipientKey = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)
const symmetricKey = b4a.alloc(sodium.crypto_secretbox_KEYBYTES)

const BroadcastPayload = schema.resolveStruct('@broadcast/payload')
const BroadcastMessage = schema.resolveStruct('@broadcast/message')

module.exports = class BroadcastEncryption extends ReadyResource {
  constructor(core, opts = {}) {
    super()

    this.core = core
    this.keyPair = opts.keyPair || null

    this.bootstrap = opts.bootstrap || null

    this._initialising = null
  }

  async _open() {
    await this.core.ready()

    this.core.on('append', this.refresh.bind(this))
  }

  _close() {
    return this.core.close()
  }

  id() {
    return this.core ? this.core.length : 0
  }

  refresh() {
    return this._getLatestKey().catch(safetyCatch)
  }

  async append(payload) {
    await this._append({ payload })
    const id = this.core.length

    await this.point(id - 2) // point to previous key

    return id
  }

  async update(key, recipients) {
    const payload = await BroadcastEncryption.encrypt(key, recipients)
    return this.append(payload)
  }

  async point(to) {
    // first pointer is null to maintain offset
    if (to < 0) {
      return this._append({ pointer: null, payload: null })
    }

    const [old, current] = await Promise.all([this.get(to), this._getLatestKey()])

    const buffer = encryptPointer(old.encryptionKey, current.encryptionKey, nonce)
    const pointer = { to: old.id, from: current.id, nonce, buffer }

    await this._append({ pointer })
  }

  async _get(index, opts) {
    return this.core.get(index, { ...opts, valueEncoding: BroadcastMessage })
  }

  async _append({ pointer, payload }) {
    return this.core.append(c.encode(BroadcastMessage, { version: 0, pointer, payload }))
  }

  async _getLatestKey(opts) {
    let id = this.core.length

    while (id > 0) {
      const block = await this._get(id - 1, opts)

      if (block && block.payload) {
        const key = {
          id,
          encryptionKey: this._unpack(block.payload)
        }

        this._setBootstrapMaybe(key)

        return key
      }

      id--
    }

    return { id: 0, encryptionKey: null }
  }

  async get(id, opts) {
    if (!this.core) {
      await this.initialised()
    }

    if (id === -1) {
      return this._getLatestKey()
    }

    if (id === 0) {
      return { id: 0, encryptionKey: null }
    }

    const block = await this._get(id - 1, opts)
    if (!block) return null // no key in core

    let encryptionKey = null

    try {
      encryptionKey = this._unpack(block.payload)
    } catch (err) {
      encryptionKey = await this.getByPointer(id)
      if (!encryptionKey) throw err
    }

    const key = { id, encryptionKey }

    this._setBootstrapMaybe(key)

    return key
  }

  _setBootstrapMaybe(key) {
    if (!this.bootstrap || this.bootstrap.id < key.id) {
      this.bootstrap = key
      this.emit('update', key.id)
    }
  }

  async getByPointer(id) {
    if (!this.bootstrap || this.bootstrap.id < id) return null

    let seq = this.bootstrap.id
    let key = this.bootstrap.encryptionKey

    while (seq > id) {
      const { pointer } = await this._get(seq)

      seq = pointer.to
      key = decryptPointer(pointer.buffer, pointer.nonce, key)
    }

    return key
  }

  _unpack(block) {
    if (!this.keyPair) throw new Error('No key pair provided')

    const encryptionKey = BroadcastEncryption.decrypt(block, this.keyPair.secretKey)
    if (!encryptionKey) throw new Error('Broadcast decryption failed')

    return encryptionKey
  }

  static PayloadEncoding = BroadcastPayload

  static encrypt(data, recipients) {
    const seed = crypto.hash([NS_KEYPAIR_SEED, data])

    sodium.crypto_box_seed_keypair(publicKey, secretKey, seed)
    sodium.crypto_generichash_batch(nonce, [NS_NONCE, publicKey])

    const broadcast = {
      publicKey,
      payload: []
    }

    for (const recipient of recipients) {
      if (recipient === null) continue

      const enc = b4a.alloc(data.byteLength + sodium.crypto_box_MACBYTES)

      sodium.crypto_sign_ed25519_pk_to_curve25519(recipientKey, recipient)
      sodium.crypto_box_easy(enc, data, nonce, recipientKey, secretKey)

      broadcast.payload.push(enc)
    }

    return broadcast
  }

  static decrypt(broadcast, recipientSecretKey) {
    const { publicKey, payload } = broadcast

    const data = b4a.alloc(payload[0].byteLength - sodium.crypto_box_MACBYTES)

    sodium.crypto_generichash_batch(nonce, [NS_NONCE, publicKey])
    sodium.crypto_sign_ed25519_sk_to_curve25519(secretKey, recipientSecretKey)

    try {
      for (const ciphertext of payload) {
        if (sodium.crypto_box_open_easy(data, ciphertext, nonce, publicKey, secretKey)) {
          return data
        }
      }
    } finally {
      b4a.fill(secretKey, 0)
    }

    return null
  }

  static verify(ciphertext, data, recipients) {
    const seed = crypto.hash([NS_KEYPAIR_SEED, data])

    sodium.crypto_box_seed_keypair(publicKey, secretKey, seed)
    sodium.crypto_generichash_batch(nonce, [NS_NONCE, publicKey])

    const received = c.decode(BroadcastPayload, ciphertext)

    if (!b4a.equals(publicKey, received.publicKey)) return false

    const expected = b4a.alloc(data.byteLength + sodium.crypto_box_MACBYTES)

    for (const target of recipients) {
      sodium.crypto_sign_ed25519_pk_to_curve25519(recipientKey, target)
      sodium.crypto_box_easy(expected, data, nonce, recipientKey, secretKey)

      let found = false

      for (const ciphertext of received.payload) {
        if (b4a.equals(ciphertext, expected)) {
          found = true
          break
        }
      }

      if (!found) return false
    }

    return true
  }
}

function encryptPointer(to, from, nonce) {
  const buffer = b4a.alloc(to.byteLength + sodium.crypto_secretbox_MACBYTES)

  sodium.crypto_generichash_batch(nonce, [NS_SYMMETRIC_NONCE, to])
  sodium.crypto_secretbox_easy(buffer, to, nonce, from)

  return buffer
}

function decryptPointer(data, nonce, key) {
  const buffer = b4a.alloc(data.byteLength - sodium.crypto_secretbox_MACBYTES)
  sodium.crypto_secretbox_open_easy(buffer, data, nonce, key)

  return buffer
}
