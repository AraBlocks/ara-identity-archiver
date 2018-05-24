'use strict'

const { info, warn, error } = require('ara-console')
const { createNetwork } = require('ara-identity-archiver/network')
const through = require('through2')
const crypto = require('ara-crypto')
const extend = require('extend')
const debug = require('debug')('ara:network:node:identity-archiver')
const pify = require('pify')
const fs = require('fs')

const conf = {
  port: 8000,
  key: null,
  keystore: null,
  dns: { loopback: false },
}

let network = null

async function start(argv) {
  if (network && network.swarm) {
    return false
  }

  const keystore = {}
  const keys = {
    remote: null,
    client: null,
    network: null,
    discovery: null,
  }

  if (null == conf.key || 'string' != typeof conf.key) {
    throw new TypeError("Expecting network key to be a string.")
  } else {
    conf.key = Buffer.alloc(16).fill(conf.key)
  }

  if (conf.keystore && 'string' == typeof conf.keystore) {
    try { await pify(fs.access)(conf.keystore) }
    catch (err) {
      throw new Error(`Unable to access keystore file '${conf.keystore}'.`)
    }

    try {
      const json = JSON.parse(await pify(fs.readFile)(conf.keystore, 'utf8'))
      const buffer = crypto.decrypt(json, {key: conf.key})
      keys.discovery = buffer.slice(0, 32)
      keys.remote = {
        publicKey: buffer.slice(32, 64),
        secretKey: buffer.slice(64, 128),
      }

      keys.client = {
        publicKey: buffer.slice(128, 160),
        secretKey: buffer.slice(160, 224),
      }

      keys.network = {
        publicKey: buffer.slice(224, 256),
        secretKey: buffer.slice(256, 318),
      }
    } catch (err) {
      debug(err)
      throw new Error(`Unable to read keystore file '${conf.keystore}'.`)
    }
  } else {
    throw new TypeError("Missing keystore file path.")
  }

  Object.assign(conf, {stream, onauthorize})
  Object.assign(conf, {network: { key: keys.discovery }})
  Object.assign(conf, {
    client: keys.client,
    remote: keys.remote,
  })

  network = createNetwork(conf)

  network.swarm.join(keys.discovery)
  network.swarm.listen(conf.port)

  network.swarm.on('connection', onconnection)
  network.swarm.on('listening', onlistening)
  network.swarm.on('close', onclose)
  network.swarm.on('error', onerror)
  network.swarm.on('peer', onpeer)

  function stream(peer) {
    return through()
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

  return true
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
        describe: 'ARA network key hex value.'
      })
      .option('keystore', {
        type: 'string',
        alias: 'K',
        describe: 'ARA network key store object'
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
