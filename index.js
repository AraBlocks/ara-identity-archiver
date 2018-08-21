const { unpack, keyRing, derive } = require('ara-network/keys')
const { info, warn, error } = require('ara-console')
const { createChannel } = require('ara-network/discovery/channel')
const { createServer } = require('ara-network/discovery')
const { Handshake } = require('ara-network/handshake')
const { readFile } = require('fs')
const { resolve } = require('path')
const multidrive = require('multidrive')
const inquirer = require('inquirer')
const through = require('through2')
const { DID } = require('did-uri')
const crypto = require('ara-crypto')
const toilet = require('toiletdb')
const mkdirp = require('mkdirp')
const debug = require('debug')('ara:network:node:identity-archiver')
const pify = require('pify')
const pump = require('pump')
const pkg = require('./package')
const net = require('net')
const rc = require('./rc')()
const ss = require('ara-secret-storage')

const conf = {
  identity: null,
  keyring: null,
  secret: null,
  name: null,
  port: 0,
  dns: {
    loopback: true
  },
}

let resolvers = null
let channel = null

async function getInstance() {
  return channel
}

async function configure(opts, program) {
  if (program) {
    const { argv } = program
      .option('i', {
        alias: 'identity',
        describe: 'Ara Identity for the network node'
      })
      .option('s', {
        alias: 'secret',
        describe: 'Shared secret key'
      })
      .option('n', {
        alias: 'name',
        describe: 'Human readable network keys name.'
      })
      .option('k', {
        alias: 'keyring',
        describe: 'Path to ARA network keys'
      })
      .option('p', {
        alias: 'port',
        describe: 'Port for network node to listen on.'
      })

    conf.port = argv.port
    conf.name = argv.name
    conf.secret = argv.secret
    conf.keyring = argv.keyring
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

  const keyring = keyRing(conf.keyring, { secret: secretKey })
  const buffer = await keyring.get(conf.name)
  const unpacked = unpack({ buffer })

  const { discoveryKey } = unpacked
  const server = net.createServer(onconnection)
  server.listen(conf.port, onlisten)

  // overload CFS roof directory to be the archive root directory
  // and then require `createCFS` after this has been overloaded
  process.env.CFS_ROOT_DIR = resolve(rc.network.identity.archive.root)
  await pify(mkdirp)(process.env.CFS_ROOT_DIR)

  // eslint-disable-next-line global-require
  const { createCFS } = require('cfsnet/create')

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

  resolvers.setMaxListeners(Infinity)
  resolvers.on('error', onerror)
  resolvers.on('peer', onpeer)

  info('%s: discovery key:', pkg.name, discoveryKey.toString('hex'))

  const nodes = rc.network.identity.archive.nodes.store
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

  function onerror(err) {
    debug(err.stack || err)

    if (err && 'EADDRINUSE' === err.code) {
      return channel.listen(0)
    }

    warn('identity-archiver: error:', err.message)
    return null
  }

  function onpeer(peer) {
    info('Got peer:', peer.id)
  }

  function onconnection(socket) {
    let kp = null
    if (process.env.DERIVE_KEY_PAIR) {
      kp = derive({ secretKey, name: conf.name })
    } else {
      kp = { publicKey, secretKey }
    }

    const handshake = new Handshake({
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
      secret,
      remote: { publicKey: unpacked.publicKey },
      domain: { publicKey: unpacked.domain.publicKey }
    })

    handshake.on('hello', onhello)
    handshake.on('error', ondone)
    handshake.on('auth', onauth)
    handshake.on('okay', onokay)

    pump(handshake, socket, handshake, ondone)

    function ondone(err) {
      if (err) {
        debug(err.stack || err)
        warn(err.message)
      }

      handshake.destroy()
      socket.destroy()
    }

    function onhello(hello) {
      info(
        'Got hello from peer: key=%s mac=%s',
        hello.publicKey.toString('hex'),
        hello.mac.toString('hex')
      )

      process.nextTick(() => {
        handshake.hello()
      })
    }

    function onauth(auth) {
      info(
        'Authenticated peer: key=%s signature=%s',
        auth.publicKey.toString('hex'),
        auth.signature.toString('hex')
      )
    }

    async function onokay(okay) {
      info('Got okay from peer: signature=%s', okay.toString('hex'))

      const reader = handshake.createReadStream()

      reader.on('data', async (data) => {
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
        socket.destroy()
      })

      async function oncreate(id, key) {
        const cfs = await pify(drives.create)({
          id: id.toString('hex'),
          key: key.toString('hex'),
        })

        info('Got archive: key=%s', key.toString('hex'))

        cfs.once('sync', () => {
          info('Did sync archive: key=%s', key.toString('hex'))
        })

        // eslint-disable-next-line no-shadow
        try {
          info('Accessing %s for "did:ara:%s"', cfs.HOME, cfs.key.toString('hex'))
          await cfs.access('.')
        } catch (err) {
          info('Waiting for update for "did:ara:%s"', cfs.key.toString('hex'))
          await new Promise(done => cfs.once('update', done))
        }

        // eslint-disable-next-line no-shadow
        try {
          info('Downloading %s for "did:ara:%s"', cfs.HOME, cfs.key.toString('hex'))
          await cfs.download('.')

          info('Reading %s for "did:ara:%s"', cfs.HOME, cfs.key.toString('hex'))
          const files = await cfs.readdir('.')

          info('Did sync files: key=%s', key.toString('hex'), files)
          info('Finished archiving AID: "did:ara:%s"', key.toString('hex'))
        } catch (err) {
          debug(err.stack || err)
          error(err.message)
          warn('Failed to sync archive for AID: "did:ara:%s"', key.toString('hex'))
          return false
        }

        return true
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
