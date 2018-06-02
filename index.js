'use strict'

const { info, warn, error } = require('ara-console')
const { createNetwork } = require('ara-identity-archiver/network')
const { createServer } = require('ara-network/discovery')
const { createCFS } = require('cfsnet/create')
const multidrive = require('multidrive')
const archiver = require('ara-identity-archiver')
const through = require('through2')
const secrets = require('ara-network/secrets')
const crypto = require('ara-crypto')
const extend = require('extend')
const toilet = require('toiletdb')
const debug = require('debug')('ara:network:node:identity-archiver')
const pify = require('pify')
const pump = require('pump')
const lpm = require('length-prefixed-message')
const pkg = require('./package')
const fs = require('fs')

const conf = {
  port: 8000,
  key: null,
  keystore: null,
  dns: { loopback: true },
  nodes: './nodes.json'
}

let resolvers = null
let network = null

async function start(argv) {
  if (network && network.swarm) {
    return false
  }

  const keystore = {}
  const keys = {
    discoveryKey: null,
    remote: null,
    client: null,
    network: null,
  }

  if (null == conf.key || 'string' != typeof conf.key) {
    throw new TypeError("Expecting network key to be a string.")
  }

  if (conf.keystore && 'string' == typeof conf.keystore) {
    try { await pify(fs.access)(conf.keystore) }
    catch (err) {
      throw new Error(`Unable to access keystore file '${conf.keystore}'.`)
    }

    try {
      const { keystore } = JSON.parse(await pify(fs.readFile)(conf.keystore, 'utf8'))
      Object.assign(keys, secrets.decrypt({keystore}, {key: conf.key}))
    } catch (err) {
      debug(err)
      throw new Error(`Unable to read keystore file '${conf.keystore}'.`)
    }
  } else {
    throw new TypeError("Missing keystore file path.")
  }

  Object.assign(conf, {onstream})
  Object.assign(conf, {discoveryKey: keys.discoveryKey})
  Object.assign(conf, {
    network: keys.network,
    client: keys.client,
    remote: keys.remote,
  })

  resolvers = createServer({
    stream(peer) {
      const { port } = resolvers.address()
      if (peer && peer.channel && port != peer.port) {
        for (const cfs of drives.list()) {
          if (0 == Buffer.compare(cfs.discoveryKey, peer.channel)) {
            return cfs.replicate({live: true})
          }
        }
      }
      const stream = through()
      stream.end()
      return stream
    }
  })

  info("%s: discovery key:", pkg.name, keys.discoveryKey.toString('hex'));

  const store = toilet(conf.nodes)
  const drives = await pify(multidrive)(store,
    async function create(opts, done) {
      const id = Buffer.from(opts.id, 'hex').toString('hex')
      const key = Buffer.from(opts.key, 'hex')
      const conf = Object.assign({}, opts, { id, key })
      const cfs = await createCFS(conf)
      resolvers.join(cfs.discoveryKey)
      return done(null, cfs)
    },

    async function close(cfs, done) {
      try { await cfs.close() }
      catch (err) { return done(err) }
      return done(null)
    })

  network = createNetwork(conf)
  network.swarm.join(keys.discoveryKey)
  network.swarm.listen(conf.port)
  network.swarm.setMaxListeners(Infinity)

  resolvers.setMaxListeners(Infinity)
  resolvers.on('error', onerror)
  resolvers.on('peer', onpeer)

  network.swarm.on('connection', onconnection)
  network.swarm.on('listening', onlistening)
  network.swarm.on('close', onclose)
  network.swarm.on('error', onerror)
  network.swarm.on('peer', onpeer)

  return true

  async function onstream(connection, peer) {
    const { discoveryKey } = keys
    const { channel } = peer
    if (channel && 0 == Buffer.compare(channel, discoveryKey)) {
      const callbacks = { onhandshake, oninit, onidx, onfin, onpkx }
      return archiver.sink.handshake(connection, peer, callbacks)
    }

    function oninit(state) {
      connection.once('readable', () => {
        info("%s: Reading PKX in from connection", pkg.name, peer.host)
      })
    }

    function onpkx(pkx) {
      info("%s: Got PKX", pkx.toString())
      connection.once('readable', () => {
        info("%s: Reading IDX in from connection", pkg.name, peer.host)
      })
    }

    function onidx(idx) {
      info("%s: Got IDX", idx.toString())
      connection.once('readable', () => {
        info("%s: Reading FIN in from connection", pkg.name, peer.host)
      })
    }

    function onfin(fin, signature) {
      info("%s: Got FIN(0xDEF)", fin.toString(), signature.toString('hex'))
      connection.once('readable', () => {
        info("%s: Reading stream in from connection", pkg.name, peer.host)
      })
    }

    async function onhandshake(state) {
      const id = state.idx.slice(3)
      const key = state.pkx.slice(3)
      const cfs = await pify(drives.create)({
        id: id.toString('hex'),
        key: key.toString('hex'),
      })

      const stream = cfs.replicate({download: true, upload: false, live: false})

      info("%s: Got archive:", pkg.name, id.toString('hex'), key.toString('hex'))

      pump(connection, stream, connection, (err) => {
        if (err) {
          debug(err)
          error(err.message)
        }
      })

      await new Promise((resolve) => cfs.once('update', resolve))
      info("%s: Did sync archive:", pkg.name, id.toString('hex'), key.toString('hex'))

      try {
        await cfs.download('.')
        const files = await cfs.readdir('.')
        info("%s: Did sync files:", pkg.name, id.toString('hex'), key.toString('hex'), files)
      } catch (err) {
        debug(err.stack || err)
        error(err.message)
        warn("%s: Empty archive!", pkg.name, id.toString('hex'), key.toString('hex'))
      } finally {
      }
    }
  }

  function onauthorize(id, done) {
    if (0 == Buffer.compare(id, keys.remote.publicKey)) {
      info("Authorizing peer:", id.toString('hex'))
      done(null, true)
    } else {
      info("Denying peer:", id.toString('hex'))
      done(null, false)
    }
  }

  function onconnection() {
    info("Connected to peer:")
  }

  function onerror(err) {
    debug("error:", err)
    if (err && 'EADDRINUSE' == err.code) {
      return network.swarm.listen(0)
    } else {
      warn("identity-archiver: error:", err.message)
    }
  }

  function onpeer(peer) {
    info("Got peer:", peer.id)
  }

  function onclose() {
    warn("identity-archiver: Closed")
  }

  function onlistening() {
    const { port } = network.swarm.address()
    info("identity-archiver: Listening on port %s", port)
  }
}

async function stop(argv) {
  if (null == network || null == network.swarm) {
    return false
  }

  warn("identity-archiver: Stopping network.swarm")
  network.swarm.close(onclose)

  return true

  function onclose() {
    network.swarm = null
  }
}

async function configure(opts, program) {
  if (program) {
    const { argv } = program
      .option('key', {
        type: 'string',
        alias: 'k',
        describe: 'Network key.'
      })
      .option('keystore', {
        type: 'string',
        alias: 'K',
        describe: 'Network keystore file path'
      })

    if (argv.keystore) { opts.keystore = argv.keystore }
    if (argv.port) { opts.port = argv.port }
    if (argv.key) { opts.key = argv.key }
  }

  return extend(true, conf, opts)
}

async function getInstance(argv) {
  return network.swarm
}

module.exports = {
  getInstance,
  configure,
  start,
  stop,
}

