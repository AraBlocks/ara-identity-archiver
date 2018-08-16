const debug = require('debug')('ara:network:node:identity-archiver')
const { createChannel } = require('ara-network/discovery/channel')
const { createServer } = require('ara-network/discovery')
const { unpack, keyRing } = require('ara-network/keys')
const { Handshake } = require('ara-network/handshake')
const { info, warn, error } = require('ara-console')
const { createCFS } = require('cfsnet/create')
const multidrive = require('multidrive')
const ss = require('ara-secret-storage')
const crypto = require('ara-crypto')
const inquirer = require('inquirer')
const through = require('through2')
const { resolve } = require('path')
const { readFile } = require('fs')
const { DID } = require('did-uri')
const toilet = require('toiletdb')
const pkg = require('./package')
const mkdirp = require('mkdirp')
const pify = require('pify')
const net = require('net')
const pump = require('pump')
const rc = require('./rc')()

const conf = {
  port: 0,
  key: null,
  dns: { loopback: true },
}

let resolvers = null
let channel = null

async function getInstance() {
  return channel
}

async function configure(opts, program) {
  if (program) {
    const { argv } = program
      .option('identity', {
        alias: 'i',
        describe: 'Ara Identity for the network node'
      })
      .option('secret', {
        alias: 's',
        describe: 'Shared secret key'
      })
      .option('name', {
        alias: 'n',
        describe: 'Human readable network keys name.'
      })
      .option('keys', {
        alias: 'k',
        describe: 'Path to ARA network keys'
      })
      .option('port', {
        alias: 'p',
        describe: 'Port for network node to listen on.'
      })

    conf.port = argv.port
    conf.keys = argv.keys
    conf.name = argv.name
    conf.secret = argv.secret
    conf.identity = argv.identity
  }
}

async function start() {
  if (channel) {
    return false
  }

  channel = createChannel({ })

  let { password } = await inquirer.prompt([
    {
      type: 'password',
      name: 'password',
      message:
        'Please enter the passphrase associated with the node identity.\n' +
        'Passphrase:'
    }
  ])
  if (0 !== conf.identity.indexOf('did:ara:')) {
    conf.identity = `did:ara:${conf.identity}`
  }
  const did = new DID(conf.identity)
  const publicKey = Buffer.from(did.identifier, 'hex')

  password = crypto.blake2b(Buffer.from(password))

  const hash = crypto.blake2b(publicKey).toString('hex')
  const path = resolve(rc.network.identity.root, hash, 'keystore/ara')
  const secret = Buffer.from(conf.secret)
  const keystore = JSON.parse(await pify(readFile)(path, 'utf8'))
  const secretKey = ss.decrypt(keystore, { key: password.slice(0, 16) })

  const keyring = keyRing(conf.keys, { secret: secretKey })
  const buffer = await keyring.get(conf.name)
  const unpacked = unpack({ buffer })

  const { discoveryKey } = unpacked
  const server = net.createServer(onconnection)
  server.listen(conf.port, onlisten)

  const pathPrefix = crypto.blake2b(Buffer.from(conf.name)).toString('hex')
  // overload CFS roof directory to be the archive root directory
  process.env.CFS_ROOT_DIR = resolve(
    rc.network.identity.archive.root,
    pathPrefix
  )

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

  info('%s: discovery key:', pkg.name, discoveryKey.toString('hex'))

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

  function onlisten(err) {
    if (err) { throw err }
    const { port } = server.address()
    channel.join(discoveryKey, port)
  }

  function onconnection(socket) {
    const handshake = new Handshake({
      publicKey,
      secretKey,
      secret,
      remote: { publicKey: unpacked.publicKey },
      domain: { publicKey: unpacked.domain.publicKey }
    })

    handshake.on('hello', onhello)
    handshake.on('auth', onauth)
    handshake.on('okay', onokay)

    pump(handshake, socket, handshake, (err) => {
      if (err) {
        warn(err.message)
      }
    })

    function onhello() {
      handshake.hello()
    }

    function onauth() {
    }

    async function onokay() {
      resolvers.setMaxListeners(Infinity)
      resolvers.on('error', onerror)
      resolvers.on('peer', onpeer)

      const reader = handshake.createReadStream()

      reader.on('data', (async (data) => {
        const id = data.slice(64)
        const key = data.slice(0, 32)
        const result = await oncreate(id, key)
        const writer = handshake.createWriteStream()
        if (result) {
          writer.write(Buffer.from('ACK'))
        } else {
          writer.write(Buffer.from('ERR'))
        }
        handshake.destroy()
      }))

      async function oncreate(id, key) {
        const cfs = await pify(drives.create)({
          id: id.toString('hex'),
          key: key.toString('hex'),
        })

        info('%s: Got archive:', pkg.name, id.toString('hex'), key.toString('hex'))

        cfs.once('sync', () => {
          info('%s: Did sync archive:', pkg.name, id.toString('hex'), key.toString('hex'))
        })

        /* eslint-disable no-shadow */
        try { await cfs.access('.') } catch (err) {
          await new Promise(resolve => cfs.once('update', resolve))
        }
        /* eslint-enable no-shadow */
        try {
          await cfs.download('.')
          const files = await cfs.readdir('.')
          info('%s: Did sync files:', pkg.name, id.toString('hex'), key.toString('hex'), files)
          info('%s: Finished Archiving DID: %s', pkg.name, key.toString('hex'))
        } catch (err) {
          debug(err.stack || err)
          error(err.message)
          warn('%s: Empty archive!', pkg.name, id.toString('hex'), key.toString('hex'))
          return false
        }
        return true
      }

      function onerror(err) {
        debug('error:', err)
        if (err && 'EADDRINUSE' === err.code) {
          return channel.listen(0)
        }
        warn('identity-archiver: error:', err.message)
        return null
      }

      function onpeer(peer) {
        info('Got peer:', peer.id)
      }
    }
  }

  return true
}

async function stop() {
  if (null == channel) {
    return false
  }

  warn('identity-archiver: Stopping %s', pkg.name)
  channel.destroy(onclose)
  return true
  function onclose() {
    channel = null
  }
}

module.exports = {
  getInstance,
  configure,
  start,
  stop,
}
