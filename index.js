'use strict'

const { info, warn, error } = require('ara-console')
const network = require('ara-identity-archiver/network')
const crypto = require('ara-crypto')
const extend = require('extend')
const debug = require('debug')('ara:network:node:identity-archiver')

const conf = {
  port: 8000,
  key: null
}

let server = null

async function start(argv) {
  if (server) { return false }
  server = network.createNetwork(conf)
  server = server.swarm
  const discoveryKey = crypto.discoveryKey(Buffer.alloc(32).fill(conf.key))
  server.listen(conf.port)
  server.join(discoveryKey)

  server.on('peer',onpeer)
  server.on('connection',onconnection)
  server.on('error',onerror)
  server.on('listening',onlistening)
  server.on('close',onclose)

  function onconnection() {
    info("Connected to peer : ")
  }

  function onerror(err) {
    warn("identity-archiver: error:", err.message)
    debug("error:", err)
  }

  function onpeer(peer) {
    info("Got peer : ",peer)
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
      .option('key',{
        type: 'string',
        alias: 'k',
        describe: 'ARA network key'
      })
    if (argv.key) {
    opts.key = argv.key
    }
    if (argv.port) {
      opts.port = argv.port
    }
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
