const { resolve } = require('path')
const extend = require('extend')
const rc = require('ara-identity/rc')

const defaults = () => ({
  network: {
    identity: {
      archiver: {
        port: 0,
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

module.exports = conf => rc(extend(true, {}, defaults(), conf))
