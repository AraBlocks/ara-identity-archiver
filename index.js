'use strict'

const { info, warn, error } = require('ara-console')
const { createNetwork } = require('ara-identity-archiver/network')
const { createCFS } = require('cfsnet/create')
const archiver = require('ara-identity-archiver')
const through = require('through2')
const secrets = require('ara-network/secrets')
const crypto = require('ara-crypto')
const extend = require('extend')
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
}

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
  } else {
    conf.key = Buffer.alloc(16).fill(conf.key)
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

  info("%s: discovery key:", pkg.name, keys.discoveryKey.toString('hex'));
  network = createNetwork(conf)

  network.swarm.setMaxListeners(Infinity)
  network.swarm.join(keys.discoveryKey)
  network.swarm.listen(conf.port)

  network.swarm.on('connection', onconnection)
  network.swarm.on('listening', onlistening)
  network.swarm.on('close', onclose)
  network.swarm.on('error', onerror)
  network.swarm.on('peer', onpeer)

  function onstream(connection, peer) {
    archiver.sink.handshake(connection, peer, {
      onhandshake,
      oninit,
      onidx,
      onfin,
      onpkx,
    })
    return

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
      const cfs = await createCFS({id, key})
      const stream = cfs.replicate({download: true, upload: true})

      info("%s: Got archive:", pkg.name, id.toString('utf8'), key.toString('hex'))
      pump(connection, stream, connection, (err) => {
        if (err) { console.error(err) }
      })

      await new Promise((resolve) => cfs.once('update', resolve))
      info("%s: Did sync archive:", pkg.name, id.toString('utf8'), key.toString('hex'))

      let keystore = null
      let files = null
      let ddo = null


      try { files = await cfs.readdir('.') }
      catch (err) {
        debug(err.stack || err)
        error(err.message)
        return warn("%s: Empty archive!", pkg.name, id.toString('utf8'), key.toString('hex'))
      }

      info("%s: Did sync files:", pkg.name, id.toString('utf8'), key.toString('hex'), files)

      const expected = ['ddo.json', 'keystore']

      for (const file of expected) {
        try { ddo = await cfs.readFile(file, 'utf8') }
        catch (err) {
          debug(err.stack || err)
          error(err.message)
          return warn("%s: Failed to sync `%s'", pkg.name, file, id.toString('utf8'), key.toString('hex'))
        }

        info("%s: Did sync `%s':", pkg.name, file, id.toString('utf8'), key.toString('hex'), ddo)
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

