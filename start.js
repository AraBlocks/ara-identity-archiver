/* eslint-disable no-await-in-loop */
const { discoveryKey: createHypercoreDiscoverKey } = require('hypercore-crypto')
const { unpack, keyRing, derive } = require('ara-network/keys')
const { info, warn, error } = require('ara-console')('identity-archiver')
const { createCFSKeyPath } = require('cfsnet/key-path')
const { createChannel } = require('ara-network/discovery/channel')
const { createSwarm } = require('ara-network/discovery')
const { setInstance } = require('./instance')
const { destroyCFS } = require('cfsnet/destroy')
const { createCFS } = require('cfsnet/create')
const { Handshake } = require('ara-network/handshake')
const { readFile } = require('fs')
const { resolve } = require('path')
const multidrive = require('multidrive')
const inquirer = require('inquirer')
const LRUCache = require('lru-cache')
const protobuf = require('ara-identity/protobuf')
const hyperdb = require('hyperdb')
const { DID } = require('did-uri')
const crypto = require('ara-crypto')
const toilet = require('toiletdb')
const mkdirp = require('mkdirp')
const rimraf = require('rimraf')
const debug = require('debug')('ara:network:node:identity-archiver')
const pify = require('pify')
const pump = require('pump')
const net = require('net')
const fs = require('fs')
const rc = require('./rc')()
const ss = require('ara-secret-storage')

const CFS_UPDATE_TIMEOUT = 5000

let discoveryKey = null
let channel = null
let drives = null

async function start(conf) {
  if (channel) {
    return false
  }

  channel = createChannel({ })

  let { password } = conf

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
  const gateway = createSwarm({})
  const cache = new LRUCache({
    maxAge: 30 * 1000,
    async dispose(discoveryKey, cfs) {
      warn(
        'Disposing of %s@%s',
        cfs.key.toString('hex'),
        discoveryKey.toString('hex')
      )

      await cfs.close()
    }
  })

  server.listen(conf.port, onlisten)

  await pify(mkdirp)(process.env.CFS_ROOT_DIR)

  process.env.CFS_ROOT_DIR = resolve(rc.network.identity.archiver.data.root)

  info('discovery key:', discoveryKey.toString('hex'))

  try {
    await pify(fs.access)(rc.network.identity.archiver.data.nodes.store)
    const stat = await pify(fs.stat)(rc.network.identity.archiver.data.nodes.store)
    if (stat.isFile()) {
      // eslint-disable-next-line function-paren-newline
      throw new TypeError(
        `Expecting '${rc.network.identity.archiver.data.nodes.store}' ` +
        'to be a directory, but it is a file. Please remove it and try again.')
    }
  } catch (err) {
    debug(err)
  }

  // ensure the node store root directory exists
  await pify(mkdirp)(rc.network.identity.archiver.data.nodes.store)

  // create a path to store nodes for this archiver based on the identity
  // of this archiver
  const nodeStore = resolve(
    rc.network.identity.archiver.data.nodes.store,
    hash
  )

  // open a hyperdb instance to the node store for this archiver where
  // we map discovery keys to cfs configuration used at boot up or when
  // a peer requests to be archives
  drives = hyperdb(nodeStore, publicKey, {
    secretKey,
    firstNode: true,
    storeSecretKey: false,
    valueEncoding: 'utf-8'
  })

  drives.on('ready', () => {
    drives.list(async function (err, values) {
      for (const node of values) {
        const drive = JSON.parse(node.value)
        const storage = createCFSKeyPath(drive)

        try {
          await pify(fs.access)(resolve(storage, 'home', 'content', 'data'))
          info("Joining swarm for did:ara:%s ", drive.key)
          gateway.join(Buffer.from(drive.discoveryKey, 'hex'), { announce: true})
        } catch (err) {
          debug(err)
          warn(
            'Corrupt or invalid identity archive. Removing ',
            storage
          )
          try {
            await del(drive.key)
            await pify(rimraf)(storage)
          } catch (err0) {
            debug(err0)
            // eslint-disable-next-line function-paren-newline
            throw new Error(
              `Failed to remove ${drive.key}. ` +
              'Please remove manually before running.')
          }
        }
      }
    })
  })

  gateway.on('connection', async (connection, peer) => {
    if (drives && peer) {
      if (peer.id !== gateway.id && (peer.id || peer.channel)) {
        const discoveryKey = (peer.channel || peer.id).toString('hex')
        try {
          const node = await pify(drives.get.bind(drives))(discoveryKey)
          const config = JSON.parse(node.value)
          const cfs = cache.get(discoveryKey) || await createCFS(config)
          const stream = cfs.replicate()

          if (!cache.has(discoveryKey)) {
            cache.set(discoveryKey, cfs)
          }

          info('gateway lookup for %s', cfs.key.toString('hex'))

          return pump(connection, stream, connection, async (err) => {
            if (err) {
              onerror(err)
            } else {
              info(
                'gateway connection: %s@%s (%s:%s)',
                peer.id && peer.id.toString('hex'),
                peer.channel && peer.channel.toString('hex'),
                peer.host,
                peer.port
              )
            }
          })
        } catch (err) {
          debug(err)
        }
      }
    }

    warn(
      'gateway skip: %s@%s (%s:%s)',
      peer.id && peer.id.toString('hex'),
      peer.channel && peer.channel.toString('hex'),
      peer.host,
      peer.port
    )

    return connection.end()
  })

  gateway.on('error', (err) => {
    console.log(err)
  })

  async function put(opts, done) {
    const id = Buffer.from(opts.id, 'hex').toString('hex')
    const key = Buffer.from(opts.key, 'hex').toString('hex')

    const discoveryKey = createHypercoreDiscoverKey(Buffer.from(key, 'hex'))

    try {
      const config = Object.assign({}, opts, {
        discoveryKey: discoveryKey.toString('hex'),
        shallow: true,
        key,
        id,
      })

      return new Promise((resolve, reject) => {
        drives.put(config.discoveryKey, JSON.stringify(config), function (err, node) {
          if (err) {
            reject(err)
          }
          resolve(node.value)
        })
      })
    } catch (err) {
      debug(err)
      return err
    }
  }

  async function del(cfs, done) {

    return pify(async (done) => {
      try {
        drives.del(cfs, function (err) {
        })
        done(null)
      } catch (err) {
        done(err)
      }
    })()
  }

  function onlisten(err) {
    if (err) { throw err }
    const { port } = server.address()
    info("Joining %s on port %s", discoveryKey.toString('hex'), port)
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
    handshake.pipe(socket).pipe(handshake)

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

      socket.pause()
      const config = await put({
          id: handshake.state.remote.publicKey.toString('hex'),
          key: handshake.state.remote.publicKey.toString('hex')
      })

      const cfs = await createCFS({
          id: handshake.state.remote.publicKey.toString('hex'),
          key: handshake.state.remote.publicKey
      })

      pump(socket, cfs.replicate(), socket, async (err) => {
        if (err) {
          onerror(err)
        } else {
          try {
            const files = await cfs.readdir('.')
            info('Did sync %d files :', files.length, files)
            info('Archiving complete for did:ara:%s', handshake.state.remote.publicKey.toString('hex'))
          } catch (err) {
            debug(err)
            await cfs.close()
            return
          }
        }

        gateway.join(cfs.discoveryKey, { announce: true })
        await cfs.close()
      })

      socket.resume()
    }
  }

  await setInstance(channel)

  return true
}

module.exports = {
  start
}
