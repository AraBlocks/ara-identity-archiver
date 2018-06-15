

const { info, warn, error } = require('ara-console')
const { createNetwork } = require('ara-identity-archiver/network')
const { createServer } = require('ara-network/discovery')
const { createCFS } = require('cfsnet/create')
const { resolve } = require('path')
const multidrive = require('multidrive')
const archiver = require('ara-identity-archiver')
const through = require('through2')
const secrets = require('ara-network/secrets')
const crypto = require('ara-crypto')
const extend = require('extend')
const mkdirp = require('mkdirp')
const toilet = require('toiletdb')
const debug = require('debug')('ara:network:node:identity-archiver')
const pify = require('pify')
const pkg = require('./package')
const rc = require('./rc')()

const conf = {
  port: 0,
  key: null,
  dns: { loopback: true },
}

let resolvers = null
let network = null

async function getInstance() {
  return network.swarm
}

async function configure(opts, program) {
  if (program) {
    const { argv } = program
      .option('key', {
        type: 'string',
        alias: 'k',
        describe: 'Network key.'
      })
      .option('port', {
        type: 'number',
        alias: 'p',
        describe: 'Port for network server to listen on.'
      })

    if (argv.port) { conf.port = argv.port }
    if (argv.key) { conf.key = argv.key }
  }

  return extend(true, conf, opts)
}

async function start() {
  if (network && network.swarm) {
    return false
  }

  const keys = {
    discoveryKey: null,
    remote: null,
    client: null,
    network: null,
  }

  if (null == conf.key || 'string' !== typeof conf.key) {
    throw new TypeError('Expecting network key to be a string.')
  }

  try {
    const doc = await secrets.load(conf)
    if (null == doc || null == doc.secret) {
      throw new TypeError('Cannot start node on network without private secret key.')
    }

    const { keystore } = doc.secret
    Object.assign(keys, secrets.decrypt({ keystore }, { key: conf.key }))
  } catch (err) {
    debug(err)
    throw new Error(`Unable to read keystore for '${conf.key}'.`)
  }

  const pathPrefix = crypto.blake2b(Buffer.from(conf.key)).toString('hex')
  // overload CFS roof directory to be the archive root directory
  process.env.CFS_ROOT_DIR = resolve(
    rc.network.identity.archive.root,
    pathPrefix
  )


  Object.assign(conf, { onstream })
  Object.assign(conf, { discoveryKey: keys.discoveryKey })
  Object.assign(conf, {
    network: keys.network,
    client: keys.client,
    remote: keys.remote,
  })

  resolvers = createServer({
    stream(peer) {
      const { port } = resolvers.address()
      if (peer && peer.channel && port !== peer.port) {
        for (const cfs of drives.list()) {
          if (0 === Buffer.compare(cfs.discoveryKey, peer.channel)) {
            return cfs.replicate({ live: false })
          }
        }
      }
      return through()
    }
  })

  info('%s: discovery key:', pkg.name, keys.discoveryKey.toString('hex'));

  await pify(mkdirp)(rc.network.identity.archive.nodes.store)
  const nodes = resolve(rc.network.identity.archive.nodes.store, pathPrefix)
  const store = toilet(nodes)
  const drives = await pify(multidrive)(
    store,
    async (opts, done) => {
      const id = Buffer.from(opts.id, 'hex').toString('hex')
      const key = Buffer.from(opts.key, 'hex')
      try {
        const config = Object.assign({}, opts, { id, key, shallow: true })
        const cfs = await createCFS(config)
        // wait 1000ms to wait for resolvers swarm to boot up
        setTimeout(() => resolvers.join(cfs.discoveryKey), 1000)
        return done(null, cfs)
      } catch (err) {
        done(err)
      }
      return null
    },

    async (cfs, done) => {
      try { await cfs.close() } catch (err) { return done(err) }
      return done(null)
    }
  )

  network = createNetwork(conf)
  network.swarm.join(keys.discoveryKey)
  network.swarm.listen(conf.port)
  network.swarm.setMaxListeners(Infinity)

  resolvers.setMaxListeners(Infinity)
  resolvers.on('error', onerror)
  resolvers.on('peer', onpeer)
  resolvers.on('authorize', onauthorize)

  network.swarm.on('connection', onconnection)
  network.swarm.on('listening', onlistening)
  network.swarm.on('close', onclose)
  network.swarm.on('error', onerror)
  network.swarm.on('peer', onpeer)

  return true

  async function onstream(connection, peer) {
    const callbacks = {
      onhandshake, oninit, onidx, onfin, onpkx
    }
    connection.on('error', error)
    try { return archiver.sink.handshake(connection, peer, callbacks) } catch (err) {
      debug(err)
      try { connection.end() } catch (msg) { debug(msg) }
    }

    function oninit() {
      connection.once('readable', () => {
        info('%s: Reading PKX in from connection', pkg.name, peer.host)
      })
    }

    function onpkx(pkx) {
      info('%s: Got PKX pkx%s', pkx.slice(3).toString('hex'))
      connection.once('readable', () => {
        info('%s: Reading IDX in from connection', pkg.name, peer.host)
      })
    }

    function onidx(idx) {
      info('%s: Got IDX idx%s', idx.slice(3).toString('hex'))
      connection.once('readable', () => {
        info('%s: Reading FIN in from connection', pkg.name, peer.host)
      })
    }

    function onfin(fin, signature) {
      info('%s: Got FIN(0xDEF)', fin.toString('hex'), signature.toString('hex'))
      connection.once('readable', () => {
        info('%s: Reading stream in from connection', pkg.name, peer.host)
      })
    }

    async function onhandshake(state) {
      connection.end()

      const id = state.idx.slice(3)
      const key = state.pkx.slice(3)
      const cfs = await pify(drives.create)({
        id: id.toString('hex'),
        key: key.toString('hex'),
      })

      info('%s: Got archive:', pkg.name, id.toString('hex'), key.toString('hex'))

      cfs.once('sync', () => {
        info('%s: Did sync archive:', pkg.name, id.toString('hex'), key.toString('hex'))
      })

      /* eslint-disable no-shadow */
      try { await cfs.access('.') } catch (err) { await new Promise(resolve => cfs.once('update', resolve)) }
      /* eslint-enable no-shadow */

      try {
        await cfs.download('.')
        const files = await cfs.readdir('.')
        info('%s: Did sync files:', pkg.name, id.toString('hex'), key.toString('hex'), files)
      } catch (err) {
        debug(err.stack || err)
        error(err.message)
        warn('%s: Empty archive!', pkg.name, id.toString('hex'), key.toString('hex'))
      }
    }
    return null
  }

  function onauthorize(id, done) {
    if (0 === Buffer.compare(id, keys.remote.publicKey)) {
      info('Authorizing peer:', id.toString('hex'))
      done(null, true)
    } else {
      info('Denying peer:', id.toString('hex'))
      done(null, false)
    }
  }

  function onconnection() {
    info('Connected to peer:')
  }

  function onerror(err) {
    debug('error:', err)
    if (err && 'EADDRINUSE' === err.code) {
      return network.swarm.listen(0)
    }
    warn('identity-archiver: error:', err.message)
    return null
  }

  function onpeer(peer) {
    info('Got peer:', peer.id)
  }

  function onclose() {
    warn('identity-archiver: Closed')
  }

  function onlistening() {
    const { port } = network.swarm.address()
    info('identity-archiver: Listening on port %s', port)
  }
}

async function stop() {
  if (null == network || null == network.swarm) {
    return false
  }

  warn('identity-archiver: Stopping network.swarm')
  network.swarm.close(onclose)

  return true

  function onclose() {
    network.swarm = null
  }
}

module.exports = {
  getInstance,
  configure,
  start,
  stop,
}
