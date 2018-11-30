/* eslint-disable no-await-in-loop */
const { discoveryKey: createHypercoreDiscoverKey } = require('hypercore-crypto')
const { unpack, keyRing, derive } = require('ara-network/keys')
const { info, warn, error } = require('ara-console')('identity-archiver')
const { createCFSKeyPath } = require('cfsnet/key-path')
const { createChannel } = require('ara-network/discovery/channel')
const { createSwarm } = require('ara-network/discovery')
const { destroyCFS } = require('cfsnet/destroy')
const { createCFS } = require('cfsnet/create')
const { Handshake } = require('ara-network/handshake')
const { readFile } = require('fs')
const { resolve } = require('path')
const multidrive = require('multidrive')
const inquirer = require('inquirer')
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
const { setInstance } = require('./instance')
const lru = require('lru-cache')
const os = require('os')

const CFS_UPDATE_TIMEOUT = 5000

let channel = null

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
  server.listen(conf.port, onlisten)

  await pify(mkdirp)(process.env.CFS_ROOT_DIR)

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

  const gateway = createSwarm({
    maxConnections: os.cpus().length
  })

  const cache = lru({
    dispose(discoveryKey, cfs) {
      console.log("DISPOSE CAll")
      //destroyCFS({ cfs })
    }
  })

  let connections = 0
  let max = os.cpus().length
  gateway.on('error', onerror)
  gateway.on('peer', onpeer)
  gateway.on('connection', async (connection, peer) => {
    if (connections++ >= max) {
      return connection.end()
    }

    connection.once('end', () => connections--)
    if (drives && peer) {
      if (peer.id !== gateway.id && (peer.id || peer.channel)) {
        for (const drive of drives.list()) {
          if (drive.discoveryKey) {
            const key = peer.channel || peer.id
            const discoveryKey = Buffer.from(drive.discoveryKey, 'hex')
            if (0 === Buffer.compare(key, discoveryKey)) {
              const cfs = cache.get(drive.discoveryKey) || await createCFS(drive)
              cache.set(drive.discoveryKey, cfs)
              console.log("CACHE Length:", cache.length)
              info('gateway lookup: %s', cfs.key.toString('hex'))
              const stream = cfs.replicate({ live: false })
              return pump(connection, stream, connection, async (err) => {
                //process.nextTick(destroyCFS, { cfs })
                //cache.del(drive.discoveryKey)
                //cache.prune()
                if (err) {
                  onerror(err)
                } else {
                  gateway.emit(cfs.discoveryKey.toString('hex'))
                  info(
                    'gateway connection: %s@%s (%s:%s)',
                    peer.id && peer.id.toString('hex'),
                    peer.channel && peer.channel.toString('hex'),
                    peer.host,
                    peer.port
                  )
                }
              })
            }
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
    }

    return connection.end()
  })

  // create a path to store nodes for this archiver based on the identity
  // of this archiver
  const nodeStore = resolve(
    rc.network.identity.archiver.data.nodes.store,
    `${hash}.json`
  )

  // open a toiletdb instance to the node store for this archiver where
  // we map discovery keys to cfs configuration used at boot up or when
  // a peer requests to be archived
  let drives = null
  const store = toilet(nodeStore)

  drives = await pify(multidrive)(store, oncreatecfs, onclosefs)

  for (const drive of drives.list()) {
    if (drive instanceof Error) {
      throw drive
    }

    //console.log(drive)
    const storage = createCFSKeyPath(drive)

    try {
      console.log(await pify(fs.readdir)(resolve(storage, 'home', 'content')))
      await pify(fs.access)(resolve(storage, 'home', 'content', 'data'))
      await join(drive)
      //await pify(drives.create)(drive)
    } catch (err) {
      debug(err)
      warn(
        'Corrupt or invalid identity archive. Removing',
        drive.key.toString('hex')
      )

      try {
        //await pify(drives.close)(drive.key)
        //await pify(rimraf)(storage)
      } catch (err0) {
        debug(err0)
        // eslint-disable-next-line function-paren-newline
        throw new Error(
          `Failed to remove ${drive.key.toString('hex')}. ` +
          'Please remove manually before running.')
      }
    }
  }

  async function join(cfs) {
    return pify(async (done) => {
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

  async function watch(cfs) {
    return pify(async (done) => {
      const discoveryKey = Buffer.isBuffer(cfs.discoveryKey)
        ? cfs.discoveryKey.toString('hex')
        : cfs.discoveryKey
      gateway.once(discoveryKey, done)
    })()
  }

  async function oncreatecfs(opts, done) {
    let cfs = null
    const id = Buffer.from(opts.id, 'hex').toString('hex')
    const key = Buffer.from(opts.key, 'hex')

    try {
      const config = Object.assign({}, opts, {
        discoveryKey: createHypercoreDiscoverKey(key),
        shallow: true,
        key,
        id,
      })

console.log(config)
      done(null, config)
      // if (drives) {
      //   const list = drives.list()
      //   for (const drive of list) {
      //     if (0 === Buffer.compare(drive.key, key)) {
      //       try {
      //         await pify(drives.close)(drive.key)
      //         await pify(rimraf)(resolve(
      //           drive.partitions.home.storage,
      //           '..'
      //         ))
      //       } catch (err0) {
      //         debug(err0)
      //         // eslint-disable-next-line function-paren-newline
      //         throw new Error(
      //           `Failed to remove ${cfs.key.toString('hex').slice}. ` +
      //           'Please remove manually before running.')
      //       }
      //       list.splice(list.indexOf(drive, 1))
      //     }
      //   }
      // }
      //
      // cfs = await createCFS(config)
    } catch (err) {
      debug(err)
      done(err)
      return
    }

    //done(null, cfs)
  }

  async function onclosefs(cfs, done) {
    try {
      //await destroyCFS(cfs)
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

      reader.once('data', async (data) => {
        console.log('data......')
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
        const config = await pify(drives.create)({
          id: id.toString('hex'),
          key: key.toString('hex')
        })

        info('Got archive: key=%s', key.toString('hex'))
        await join(config)
        await watch(config)

        const cfs = cache.get(config.discoveryKey) || await createCFS(config)

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

  await setInstance(channel)

  return true
}

module.exports = {
  start
}
