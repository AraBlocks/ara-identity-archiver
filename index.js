'use strict'

const { info, warn, error } = require('ara-console')
const network = require('ara-identity-archiver/network')
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
  dns: { loopback: true },
}

let server = null

async function start(argv) {
  if (server) { return false }

  const keystore = {}
  let discoveryKey = null

  if (null == conf.key || 'string' != typeof conf.key) {
    throw new TypeError("Expecting network key to be a string.")
  } else {
    conf.key = Buffer.from(conf.key, 'hex')
  }

  if (conf.keystore && 'string' == typeof conf.keystore) {
    try { await pify(fs.access)(conf.keystore) }
    catch (err) {
      throw new Error(`Unable to access keystore file '${conf.keystore}'.`)
    }

    try {
      const json = JSON.parse(await pify(fs.readFile)(conf.keystore, 'utf8'))
      const buffer = crypto.decrypt(json, {key: conf.key})
      discoveryKey = buffer.slice(0, 32)
    } catch (err) {
      debug(err)
      throw new Error(`Unable to read keystore file '${conf.keystore}'.`)
    }
  } else {
    throw new TypeError("Missing keystore file path.")
  }


  Object.assign(conf, {stream, onauthorize})
  Object.assign(conf, {network: { key: discoveryKey }})

  server = network.createNetwork(conf)
  server = server.swarm

  server.join(discoveryKey)
  server.listen(conf.port)

  server.on('connection', onconnection)
  server.on('listening', onlistening)
  server.on('close', onclose)
  server.on('error', onerror)
  server.on('peer', onpeer)

  function stream(peer) {
    return through()
  }

  function onauthorize(id, done) {
    console.log('authorize', id);
  }

  function onconnection() {
    info("Connected to peer:")
  }

  function onerror(err) {
    debug("error:", err)
    if (err && 'EADDRINUSE' == err.code) {
      return server.listen(0)
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
    const { port } = server.address()
    info("identity-archiver: Listening on port %s", port)
  }

  return true
}

async function stop(argv) {
  if (null == server) { return false }
  warn("identity-archiver: Stopping server")
  server.close(onclose)

  function onclose() {
    server = null
  }
  return true
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
  return server
}

module.exports = {
  getInstance,
  configure,
  start,
  stop,
}
