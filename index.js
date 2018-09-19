/* eslint-disable no-await-in-loop */ const { unpack, keyRing, derive } = require('ara-network/keys')
const { info, warn, error } = require('ara-console')('identity-archiver')
const { createChannel } = require('ara-network/discovery/channel')
const { createSwarm } = require('ara-network/discovery')
const { destroyCFS } = require('cfsnet/destroy')
const { createCFS } = require('cfsnet/create')
const { Handshake } = require('ara-network/handshake')
const { readFile } = require('fs')
const { resolve } = require('path')
const multidrive = require('multidrive')
const coalesce = require('defined')
const inquirer = require('inquirer')
const { DID } = require('did-uri')
const crypto = require('ara-crypto')
const toilet = require('toiletdb')
const mkdirp = require('mkdirp')
const rimraf = require('rimraf')
const debug = require('debug')('ara:network:node:identity-archiver')
const pify = require('pify')
const pump = require('pump')
const pkg = require('./package.json')
const net = require('net')
const fs = require('fs')
const rc = require('./rc')()
const ss = require('ara-secret-storage')

const conf = {
  network: null,
  identity: null,
  keyring: null,
  secret: null,
  port: 0,

  dns: {
    loopback: true
  },
}

const CFS_UPDATE_TIMEOUT = 5000

let channel = null

async function getInstance() {
  return channel
}

async function configure(opts, program) {
  let argv = {}
  if (program) {
    program
      .wrap(null)
      .version('version', 'Show version number', pkg.version)
      .group([ 'identity', 'secret', 'keyring', 'network' ], 'Network Options:')
      .option('identity', {
        alias: 'i',
        default: rc.network.identity.whoami,
        requiresArg: true,
        required: true,

        defaultDescription: (
          rc.network.identity.whoami
            ? `${rc.network.identity.whoami.slice(0, 16)}...`
            : undefined
        ),

        describe:
`A valid, local, and resolvable Ara identity DID
URI of the owner of the given keyring. You will be
prompted for the associated passphrase`,
      })
      .option('secret', {
        alias: 's',
        describe: 'Shared secret key for the associated network keys',
        required: true,
        requiresArg: true,
      })
      .option('keyring', {
        alias: 'k',
        default: rc.network.identity.keyring,
        describe: 'Path to Ara network keyring file',
        required: true,
        requiresArg: true,
      })
      .option('network', {
        alias: 'n',
        describe: 'Human readable network name for keys in keyring',
        required: true,
        requiresArg: true,
      })

    program.group([ 'port' ], 'Server Options:')
      .option('port', {
        alias: 'p',
        describe: 'Port for network node to listen on.'
      })

    // eslint-disable-next-line prefer-destructuring
    argv = program.argv
  }

  conf.port = select('port', argv, opts, conf)
  conf.secret = select('secret', argv, opts, conf)
  conf.keyring = select('keyring', argv, opts, conf)
  conf.network = select('network', argv, opts, conf) || argv.name
  conf.identity = select('identity', argv, opts, conf)

  if (argv.name && !argv.network) {
    warn('Please use \'--network\' instead of \'--name\'.')
  }

  // overload CFS roof directory to be the archive root directory
  // and then require `createCFS` after this has been overloaded
  process.env.CFS_ROOT_DIR = resolve(rc.network.identity.archive.root)

  return conf

  function select(k, ...args) {
    return coalesce(...args.map(o => o[k]))
  }
}

async function start(argv) {
  if (channel) {
    return false
  }

  channel = createChannel({ })

  let { password } = argv

  if (!password) {
    const res = await inquirer.prompt([ {
      type: 'password',
      name: 'password',
      message:
      'Please enter the passphrase associated with the node identity.\n' +
      'Passphrase:'
    } ])

    // eslint-disable-next-line
    password = res.password
  }

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
  const buffer = await keyring.get(conf.network)
  const unpacked = unpack({ buffer })

  const { discoveryKey } = unpacked
  const server = net.createServer(onconnection)
  server.listen(conf.port, onlisten)

  await pify(mkdirp)(process.env.CFS_ROOT_DIR)

  info('discovery key:', discoveryKey.toString('hex'))

  try {
    await pify(fs.access)(rc.network.identity.archive.nodes.store)
    const stat = await pify(fs.stat)(rc.network.identity.archive.nodes.store)
    if (stat.isFile()) {
      // eslint-disable-next-line function-paren-newline
      throw new TypeError(
        `Expecting '${rc.network.identity.archive.nodes.store}' ` +
        'to be a directory, but it is a file. Please remove it and try again.')
    }
  } catch (err) {
    debug(err)
  }

  // ensure the node store root directory exists
  await pify(mkdirp)(rc.network.identity.archive.nodes.store)

  const gateway = createSwarm({ })

  gateway.on('error', onerror)
  gateway.on('peer', onpeer)
  gateway.on('connection', (connection, peer) => {
    if (drives && peer && peer.channel) {
      for (const cfs of drives.list()) {
        if (cfs && cfs.discoveryKey) {
          if (0 === Buffer.compare(peer.channel, cfs.discoveryKey)) {
            const stream = cfs.replicate({ live: false })
            info('gateway lookup: %s', cfs.key.toString('hex'))
            return pump(connection, stream, connection, (err) => {
              if (err) {
                onerror(err)
              } else {
                info('gateway connection: %s', cfs.discoveryKey.toString('hex'))
              }
            })
          }
        }
      }

      warn('gateway skip: %s', peer.channel)
    }

    return connection.end()
  })

  // create a path to store nodes for this archiver based on the identity
  // of this archiver
  const nodeStore = resolve(
    rc.network.identity.archive.nodes.store,
    `${hash}.json`
  )

  // open a toiletdb instance to the node store for this archiver where
  // we map discovery keys to cfs configuration used at boot up or when
  // a peer requests to be archived
  let drives = null
  const store = toilet(nodeStore)

  drives = await pify(multidrive)(store, oncreatecfs, onclosefs)

  for (const cfs of drives.list()) {
    if (cfs instanceof Error) {
      throw cfs
    }

    try {
      await pify(fs.access)(resolve(
        cfs.partitions.home.storage,
        'content',
        'data'
      ))

      await join(cfs)
    } catch (err) {
      debug(err)
      warn(
        'Corrupt or invalid identity archive. Removing',
        cfs.key.toString('hex')
      )

      try {
        await pify(drives.close)(cfs.key)
        await pify(rimraf)(resolve(
          cfs.partitions.home.storage,
          '..'
        ))
      } catch (err0) {
        debug(err0)
        // eslint-disable-next-line function-paren-newline
        throw new Error(
          `Failed to remove ${cfs.key.toString('hex').slice}. ` +
          'Please remove manually before running.')
      }
    }
  }

  async function join(cfs) {
    return pify((done) => {
      process.nextTick(() => {
        gateway.join(cfs.discoveryKey, { announce: true })
        process.nextTick(done, null)
        info(
          'join: %s...@%s',
          cfs.key.slice(0, 8).toString('hex'),
          cfs.discoveryKey.toString('hex')
        )
      })
    })()
  }

  async function oncreatecfs(opts, done) {
    let cfs = null
    const id = Buffer.from(opts.id, 'hex').toString('hex')
    const key = Buffer.from(opts.key, 'hex')

    try {
      const config = Object.assign({}, opts, {
        shallow: true,
        latest: true,
        key,
        id,
      })

      cfs = await createCFS(config)
    } catch (err) {
      debug(err)
      done(err)
      return
    }

    done(null, cfs)
  }

  async function onclosefs(cfs, done) {
    try {
      await destroyCFS({ cfs })

      if (gateway) {
        try {
          gateway.leave(cfs.discoveryKey)
        } catch (err) {
          void err
        }
      }

      done(null)
    } catch (err) {
      done(err)
    }
  }

  function onlisten(err) {
    if (err) { throw err }
    const { port } = server.address()
    channel.join(discoveryKey, port)
  }

  function onerror(err) {
    debug(err.stack || err)
    warn('error:', err.message)
  }

  function onpeer(peer) {
    debug('Got peer:', peer.id)
  }

  function onconnection(socket) {
    const kp = derive({ secretKey, name: conf.network })
    const handshake = new Handshake({
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
      secret,
      remote: { publicKey: unpacked.publicKey },
      domain: { publicKey: unpacked.domain.publicKey }
    })

    let closed = false

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

      if (!closed) {
        handshake.destroy()
        socket.destroy()
        closed = true
      }
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
        const result = await archive(id, key)

        if (!closed) {
          const writer = handshake.createWriteStream()

          if (result) {
            writer.write(Buffer.from('ACK'))
          } else {
            writer.write(Buffer.from('ERR'))
          }

          handshake.destroy()
          socket.destroy()
        }
      })

      async function archive(id, key) {
        const pending = []
        const cfs = await pify(drives.create)({
          id: id.toString('hex'),
          key: key.toString('hex')
        })

        await join(cfs)

        info('Got archive: key=%s', key.toString('hex'))

        try {
          info('Accessing %s for "did:ara:%s"', cfs.HOME, cfs.key.toString('hex'))
          await cfs.access(cfs.HOME)
        } catch (err) {
          info('Waiting for update for "did:ara:%s"', cfs.key.toString('hex'))
          await Promise.race([
            new Promise(done => cfs.once('sync', done)),
            new Promise(done => cfs.once('update', done)),
            new Promise(done => setTimeout(done, CFS_UPDATE_TIMEOUT))
          ])
        }

        async function visit(dir) {
          const files = await cfs.readdir(dir)
          for (const file of files) {
            const filename = resolve(dir, file)
            const stat = await cfs.stat(filename)
            if (stat && stat.isFile()) {
              pending.push(filename)
            } else if (stat && stat.isDirectory()) {
              visit(filename)
            }
          }
        }

        try {
          info('Reading %s directory', cfs.HOME)

          await visit(cfs.HOME)

          // wait for all files to download
          info('Waiting for %d files to download', pending.length)
          await Promise.all(pending.map(filename => cfs.readFile(filename)))

          info(
            'Did sync identity archive for: "did:ara:%s"',
            key.toString('hex'),
            pending
          )
        } catch (err) {
          debug(err.stack || err)
          error(err.message)
          warn(
            'Failed to sync identity archive for: "did:ara:%s"',
            key.toString('hex')
          )

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

  warn('Stopping')
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
