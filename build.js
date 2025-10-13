const path = require('path')
const Hyperschema = require('hyperschema')

const SPEC = path.join(__dirname, 'spec/broadcast-encryption')

const schema = Hyperschema.from(SPEC, { versioned: true })
const broadcast = schema.namespace('broadcast')

broadcast.register({
  name: 'payload',
  fields: [
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

broadcast.register({
  name: 'pointer',
  fields: [
    {
      name: 'to',
      type: 'uint',
      required: true
    },
    {
      name: 'from',
      type: 'uint',
      required: true
    },
    {
      name: 'nonce',
      type: 'buffer',
      required: true
    },
    {
      name: 'buffer',
      type: 'buffer',
      required: true
    }
  ]
})

broadcast.register({
  name: 'message',
  fields: [
    {
      name: 'version',
      type: 'uint',
      required: true
    },
    {
      name: 'payload',
      type: '@broadcast/payload',
      required: false
    },
    {
      name: 'pointer',
      type: '@broadcast/pointer',
      required: false
    }
  ]
})

Hyperschema.toDisk(schema, SPEC)
