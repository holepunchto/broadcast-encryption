const sodium = require('sodium-universal')
const ReadyResource = require('ready-resource')
const DefaultEncryption = require('hypercore/lib/default-encryption.js')
const HypercoreEncryption = require('hypercore-encryption')
const crypto = require('hypercore-crypto')
const c = require('compact-encoding')
const b4a = require('b4a')
const rrp = require('resolve-reject-promise')

const [DEFAULT_NAMESPACE, GENESIS_ENTROPY, NS_NONCE, NS_KEYPAIR_SEED] = crypto.namespace(
  'broadcast-encryption',
  4
)

// ephemeral state
const nonce = b4a.alloc(sodium.crypto_stream_NONCEBYTES)
const hash = nonce.subarray(0, sodium.crypto_generichash_BYTES_MIN)
const secretKey = b4a.alloc(sodium.crypto_box_SECRETKEYBYTES)
const publicKey = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)
const recipientKey = b4a.alloc(sodium.crypto_box_PUBLICKEYBYTES)

const PayloadArray = c.array(c.buffer)

const EncryptionPayload = {
  preencode(state, m) {
    c.buffer.preencode(state, m.nonce)
    c.fixed32.preencode(state, m.publicKey)
    PayloadArray.preencode(state, m.payload)
  },
  encode(state, m) {
    c.buffer.encode(state, m.nonce)
    c.fixed32.encode(state, m.publicKey)
    PayloadArray.encode(state, m.payload)
  },
  decode(state) {
    return {
      nonce: c.buffer.decode(state),
      publicKey: c.fixed32.decode(state),
      payload: PayloadArray.decode(state)
    }
  }
}

module.exports = class BroadcastEncryption extends ReadyResource {
  constructor(core, opts = {}) {
    super()

    this.core = core || null

    this.keyPair = opts.keyPair || null
    this.genesisEntropy = opts.genesis || null

    this.encryption = new HypercoreEncryption(this.get.bind(this))

    this._initialising = null
  }

  async _open() {
    await this.initialised()
    await this.core.ready()
  }

  initialised() {
    if (this.core !== null) return this.core.ready()
    if (this._initialising) return this._initialising

    this._initialising = rrp()

    return this._initialising.promise
  }

  _close() {
    if (this._initialising) {
      this._initialising.reject(new Error('Encryption closed'))
      this._initialising = null
    }

    if (this.core) return this.core.close()
  }

  id() {
    return this.core ? this.core.length : 0
  }

  async update(key, recipients) {
    const payload = await BroadcastEncryption.encrypt(key, recipients)
    await this.core.append(payload)
  }

  createEncryptionProvider (opts) {
    return this.encryption.createEncryptionProvider(opts)
  }

  async get(id, opts) {
    if (!this.core) {
      await this.initialised()
    }

    if (id === -1) id = this.core.length

    if (id === 0) {
      return {
        id: 0,
        entropy: this.genesisEntropy
      }
    }

    const payload = await this.core.get(id - 1, opts)
    if (!payload) return null

    if (!this.keyPair) throw new Error('No key pair provided')

    const entropy = await BroadcastEncryption.decrypt(payload, this.keyPair.secretKey)

    if (!entropy) throw new Error('Broadcast decryption failed')

    return {
      id,
      entropy
    }
  }

  static encrypt(data, recipients) {
    const seed = crypto.hash([NS_KEYPAIR_SEED, data])

    sodium.crypto_box_seed_keypair(publicKey, secretKey, seed)
    sodium.crypto_generichash_batch(nonce, [NS_NONCE, publicKey])

    const payload = {
      publicKey,
      payload: []
    }

    for (const recipient of recipients) {
      if (recipient === null) continue

      const enc = b4a.alloc(data.byteLength + sodium.crypto_box_MACBYTES)

      sodium.crypto_sign_ed25519_pk_to_curve25519(recipientKey, recipient)
      sodium.crypto_box_easy(enc, data, nonce, recipientKey, secretKey)

      payload.payload.push(enc)
    }

    return c.encode(EncryptionPayload, payload)
  }

  static decrypt(ciphertext, recipientSecretKey) {
    const { publicKey, payload } = c.decode(EncryptionPayload, ciphertext)

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

    const received = c.decode(EncryptionPayload, ciphertext)

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
