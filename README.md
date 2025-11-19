# broadcast-encryption

Distribute encryption keys to a dynamic set of receivers

## Usage

```js
const core = new Hypercore(storage)
const broadcast = new BroadcastEncryption(core, { keyPair })

const encryptionKey = Buffer.alloc(32)

// distribute key to everyone
await broadcast.update(encryptionKey, [peer1, peer2, peer3])

encryptionKey.fill(0xff) // update encryption key

// distribute new key to everyone except peer3
await broadcast.update(encryptionKey, [peer1, peer2])

await broadcast.get(id) // get the encryption key corresponding to id
```

## API

#### `const broadcast = new BroadcastEncryption(core, opts)`

Instantiate a new broadcast instance.

`opts` include:

```
{
  keyPair, // receiver key pair used for decryption
  bootstrap // initial key information to use
}
```

#### `const current = broadcast.id()`

The current encryption key id.

#### `const id = await broadcast.append(payload)`

Append an encrypted `payload`, usually created by `BroadcastEncryption.encrypt()`. Returns the key's `id`.

#### `const id = await broadcast.update(key, recipients)`

Distribute the updated `key` to all members of `recipients`. Returns the update's `id`.

#### `const { id, encryptionKey } = await broadcast.get(id, opts = {})`

Get the encryption key corresponding to `id`.

If `id` is passed as `-1`, the latest encryption key shall be returned.

`opts` are passed to the underlying `core.get()`.

#### `broadcast.on('update', (id) => {})`

An `update` event is emitted when a new encryption key is loaded.

#### `const payload = BroadcastEncryption.encrypt(data, recipients)`

Static helper to broadcast encrypt a message.

#### `const data = BroadcastEncryption.decrypt(payload, recipientSecretKey)`

Static helper to decrypt a broadcast encrypted message.

#### `const payload = BroadcastEncryption.verify(payload, data, recipients)`

Static helper to verify a `payload`. Returns true if all members on `recipients` can decrypt `data`.

## License

Apache-2.0
