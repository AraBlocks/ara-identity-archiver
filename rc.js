const { resolve } = require('path')
const extend = require('extend')
const rc = require('ara-runtime-configuration')

const defaults = () => ({
  network: {
    identity: {
      archive: {
        root: resolve(rc().data.root, 'identities', 'archive'),
        nodes: {
          store: resolve(rc().data.root, 'identities', 'archive', 'nodes')
        }
      },
      root: resolve(rc().data.root, 'identities')
    }
  }
})

module.exports = conf => rc(extend(true, defaults(), conf))
