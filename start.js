/* eslint-disable no-await-in-loop */
const { discoveryKey: createHypercoreDiscoverKey } = require('hypercore-crypto')
const { unpack, keyRing, derive } = require('ara-network/keys')
const { Identity, Archive } = require('ara-identity/protobuf/messages')
const { createCFSKeyPath } = require('cfsnet/key-path')
const { createChannel } = require('ara-network/discovery/channel')
const { createSwarm } = require('ara-network/discovery')
const { setInstance } = require('./instance')
const { info, warn } = require('ara-console')('identity-archiver')
const { createCFS } = require('cfsnet/create')
const { Handshake } = require('ara-network/handshake')
const { readFile } = require('fs')
const { resolve } = require('path')
const inquirer = require('inquirer')
const LRUCache = require('lru-cache')
const hyperdb = require('hyperdb')
const { DID } = require('did-uri')
const crypto = require('ara-crypto')
const mkdirp = require('mkdirp')
const rimraf = require('rimraf')
const debug = require('debug')('ara:network:node:identity-archiver')
const pify = require('pify')
const pump = require('pump')
const net = require('net')
const fs = require('fs')
const rc = require('./rc')()
const ss = require('ara-secret-storage')

const locks = {}

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
    async dispose(key, cfs) {
      warn(
        'Disposing of %s@%s',
        cfs.key.toString('hex'),
        key.toString('hex')
      )

      await cfs.close()
    }
  })

  channel.on('close', () => {
    server.close()
    gateway.destroy()
  })

  server.listen(conf.port, onlisten)

  await pify(mkdirp)(process.env.CFS_ROOT_DIR)

  process.env.CFS_ROOT_DIR = resolve(rc.network.identity.archiver.data.root)

  info('discovery key:', discoveryKey.toString('hex'))

  try {
    const storePath = rc.network.identity.archiver.data.nodes.store
    await pify(fs.access)(storePath)
    const stat = await pify(fs.stat)(storePath)
    if (stat.isFile()) {
      // eslint-disable-next-line function-paren-newline
      throw new TypeError(
        `Expecting '${storePath}' ` +
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
    drives.list(async (err, values) => {
      for (const node of values) {
        const drive = JSON.parse(node.value)
        const storage = createCFSKeyPath(drive)

        try {
          await pify(fs.access)(resolve(storage, 'home', 'content', 'data'))
          info('Joining swarm for did:ara:%s ', drive.key)
          gateway.join(Buffer.from(drive.discoveryKey, 'hex'), { announce: true })
        } catch (err0) {
          debug(err0)
          warn(
            'Corrupt or invalid identity archive. Removing ',
            storage
          )
          try {
            await del(node.key)
            await pify(rimraf)(storage)
          } catch (err1) {
            debug(err1)
            // eslint-disable-next-line function-paren-newline
            throw new Error(
              `Failed to remove ${node.key}. ` +
              'Please remove manually before running.')
          }
        }
      }
    })
  })

  gateway.on('connection', async (connection, peer) => {
    if (drives && peer) {
      if (peer.id !== gateway.id && (peer.id || peer.channel)) {
        // eslint-disable-next-line no-shadow
        const channel = (peer.channel || peer.id)
        try {
          const peerDiscoveryKey = channel.toString('hex')

          if (
            true === Buffer.isBuffer(channel) &&
            0 === Buffer.compare(channel, gateway.id)
          ) {
            debug('Skipping loopback replication for channel:', channel.toString('hex'))
            return connection.end()
          }

          const node = await pify(drives.get.bind(drives))(peerDiscoveryKey)
          const config = JSON.parse(node.value)
          const cfs = cache.get(peerDiscoveryKey) || await createCFS(config)

          if (!cache.has(peerDiscoveryKey)) {
            cache.set(peerDiscoveryKey, cfs)
          }

          const stream = cfs.replicate({
            download: true,
            upload: true,
            live: false,
          })

          debug('gateway lookup for %s', cfs.key.toString('hex'))

          return pump(connection, stream, connection, async (err) => {
            if (err) {
              onerror(err)
            } else {
              debug(
                'gateway connection: %s@%s (%s:%s)',
                peer.id && peer.id.toString('hex'),
                peer.channel && peer.channel.toString('hex'),
                peer.host,
                peer.port
              )
            }

            await cfs.close()
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
    debug(err)
  })

  async function lock(id) {
    if (locks[id]) {
      await locks[id]
    }

    let unlock = null
    locks[id] = new Promise((done) => { unlock = done })
    return unlock
  }

  async function put(opts) {
    const id = Buffer.from(opts.id, 'hex').toString('hex')
    const key = Buffer.from(opts.key, 'hex').toString('hex')
    // eslint-disable-next-line no-shadow
    const discoveryKey = createHypercoreDiscoverKey(Buffer.from(key, 'hex'))

    try {
      const config = Object.assign({}, opts, {
        sparseMetadata: true,
        discoveryKey: discoveryKey.toString('hex'),
        shallow: true,
        latest: true,
        sparse: true,
        key,
        id,
      })

      return new Promise((res, rej) => {
        drives.put(config.discoveryKey, JSON.stringify(config), (err) => {
          if (err) {
            rej(err)
          } else {
            res(config)
          }
        })
      })
    } catch (err) {
      debug(err)
      throw err
    }
  }

  async function del(key) {
    return pify(async (done) => {
      drives.del(key, (err) => {
        if (err) {
          done(err)
        } else {
          done()
        }
      })
    })()
  }

  function onlisten(err) {
    if (err) { throw err }
    const { port } = server.address()
    info('Joining %s on port %s', discoveryKey.toString('hex'), port)
    channel.join(discoveryKey, port)
  }

  function onerror(err) {
    debug(err.stack || err)
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

      const key = handshake.state.remote.publicKey.toString('hex')
      const id = key
      let cfs = null

      socket.once('error', () => { closed = true })
      socket.once('closed', () => { closed = true })

      const unlock = await lock(id)
      const opts = await put({ id, key })

      if (closed) {
        await cleanup()
        return
      }

      try {
        cfs = await createCFS(opts)
      } catch (err) {
        await cleanup(err)
        return
      }

      let cwd = '/home'
      let stream = cfs.replicate({
        download: true,
        upload: false,
        live: false,
      })

      const whitelist = new Set(rc.network.identity.archiver.files.whitelist)
      const blacklist = new Set(rc.network.identity.archiver.files.blacklist)

      const regexify = s => new RegExp(`^${s}$`)
      const matchesBlacklist = filename => [ ...blacklist ]
        .map(regexify)
        .some(regex => regex.test(filename))

      const matchesWhitelist = filename => [ ...whitelist ]
        .map(regexify)
        .some(regex => regex.test(filename))

      const files = []
      const reads = []

      stream.on('handshake', onhandshake)

      pump(socket, stream, socket, async (err) => {
        if (err) {
          onerror(err)
        }
      })

      async function cleanup(err) {
        cache.del(cfs.discoveryKey.toString('hex'))

        if (null !== stream) {
          stream.end()
          stream.destroy(err)
          socket.destroy()
          stream = null
        }

        if (null !== cfs) {
          await cfs.close()
        }

        await unlock()
      }

      async function waitForFile(filename) {
        try {
          await cfs.access(filename)
        } catch (err) {
          await Promise.race([
            new Promise(cb => cfs.once('sync', cb)),
            new Promise(cb => cfs.once('update', cb)),
          ])
        }
      }

      async function stat(filename) {
        try {
          return await cfs.stat(filename)
        } catch (err) {
          debug(err)
          return null
        }
      }

      async function visit(entries) {
        const pwd = cwd
        for (const file of entries) {
          const filename = resolve(cwd, file)

          await waitForFile(filename)

          const stats = await stat(filename)

          if (stats) {
            if (stats.isFile()) {
              if (!matchesBlacklist(filename) && matchesWhitelist(filename)) {
                files.push(filename)
              }
            } else if (stats.isDirectory()) {
              cwd = filename
              await visit(await cfs.readdir(filename))
              cwd = pwd
            }
          }
        }
      }

      async function onhandshake() {
        // assume shallow by default
        let request = { shallow: true }

        try {
          const decoded = Archive.decode(stream.remoteUserData)
          const { signature } = decoded
          delete decoded.signature
          const digest = crypto.blake2b(Archive.encode(decoded))
          const verified = crypto.verify(
            signature,
            digest,
            handshake.state.remote.publicKey
          )

          if (verified) {
            request = decoded
          }
        } catch (err) {
          debug(err)
        }

        debug('Archive request', request)

        whitelist.add('/home/ddo.json')

        try {
          if (true === request.shallow) {
            blacklist.add('/home/identity')
            blacklist.add('/home/schema.proto')
            blacklist.add('/home/keystore/ara')
            blacklist.add('/home/keystore/eth')
          } else {
            let identityBuffer = null
            let verified = false

            // the identity file may not be present meaning the archive _could_
            // be a shallow archive but the replication stream did not send an
            // Archive message in the replication user data
            try {
              await waitForFile('/home/identity')
              identityBuffer = await cfs.readFile('/home/identity')
            } catch (err) {
              debug(err)
            }

            if (null !== identityBuffer) {
              const packedIdentity = Identity.decode(identityBuffer)
              const { proof } = packedIdentity
              const digest = Identity.encode({
                files: packedIdentity.files,
                did: packedIdentity.did,
                key: packedIdentity.key,
              })

              verified = crypto.verify(
                proof.signature,
                digest,
                handshake.state.remote.publicKey
              )

              if (true !== verified) {
                throw new Error('Identity buffer failed signature failed verification')
              }

              whitelist.add('/home/identity')
              whitelist.add('/home/schema.proto')
              whitelist.add('/home/keystore/ara')
              whitelist.add('/home/keystore/eth')
            }
          }

          await cfs.access(cwd)

          try {
            await visit([ ...whitelist ])
          } catch (err) {
            debug(err)
          }

          for (const file of files) {
            info('Reading file: %s', file)
            reads.push(cfs.readFile(file))
          }

          await Promise.all(reads)

          info('Did sync %d files :', files.length, files)
          info('Archiving complete for did:ara:%s', handshake.state.remote.publicKey.toString('hex'))
          gateway.join(cfs.discoveryKey, { announce: true })
        } catch (err0) {
          debug(err0)
        }

        await cleanup()
      }

      socket.resume()
    }
  }

  await setInstance(channel)

  return true
}

module.exports = {
  start
}
