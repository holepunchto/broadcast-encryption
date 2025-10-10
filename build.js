const path = require('path')
const Hyperschema = require('hyperschema')

const SPEC = path.join(__dirname, 'spec/broadcast-encryption')

const schema = Hyperschema.from(SPEC, { versioned: true })
const broadcast = schema.namespace('broadcast')

broadcast.register({
  name: 'payload',
  fields: [
    {
      name: 'version',
      type: 'uint',
      required: true
    },
    {
      name: 'nonce',
      type: 'buffer',
      required: true
    },
    {
      name: 'publicKey',
      type: 'fixed32',
      required: true
    },
    {
      name: 'payload',
      type: 'buffer',
      array: true,
      required: true
    }
  ]
})

Hyperschema.toDisk(schema, SPEC)
