const { resolve } = require('path')
const { warn } = require('ara-console')('identity-archiver')
const coalesce = require('defined')
const pkg = require('./package.json')
const rc = require('./rc')()

const conf = {
  network: null,
  identity: null,
  keyring: null,
  secret: null,
  port: 0,
  dns: {
    loopback: false
  }
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
        requiresArg: true,
        required: true,
        default:
          rc.network.identity.archiver.whoami ||
          rc.network.identity.whoami ||
          rc.network.whoami,

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
        default:
          rc.network.identity.archiver.secret ||
          rc.network.identity.secret ||
          rc.network.secret,
      })
      .option('keyring', {
        alias: 'k',
        describe: 'Path to Ara network keyring file',
        required: true,
        requiresArg: true,
        default:
          rc.network.identity.archiver.keyring ||
          rc.network.identity.keyring ||
          rc.network.keyring,
      })
      .option('network', {
        alias: 'n',
        describe: 'Human readable network name for keys in keyring',
        required: true,
        requiresArg: true,
        default: rc.network.identity.archiver.network
      })

    program.group([ 'port' ], 'Server Options:')
      .option('port', {
        alias: 'p',
        describe: 'Port for network node to listen on.',
        default: rc.network.identity.archiver.port
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
  process.env.CFS_ROOT_DIR = resolve(rc.network.identity.archiver.data.root)

  return conf

  function select(k, ...args) {
    return coalesce(...args.map(o => o[k]))
  }
}

module.exports = {
  configure
}
