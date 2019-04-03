const { resolve } = require('path')
const extend = require('extend')
const rc = require('ara-identity/rc')

const defaults = () => ({
  network: {
    identity: {
      archiver: {
        port: 0,
        files: {
          whitelist: [],
          blacklist: [],
        },
        data: {
          root: resolve(rc().data.root, 'identities', 'archiver'),
          nodes: {
            store: resolve(rc().data.root, 'identities', 'archiver', 'nodes')
          }
        }
      }
    }
  }
})

module.exports = conf => extend(true, {}, defaults(), rc(conf))
