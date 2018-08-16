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
      root: resolve(rc().data.root, 'identities'),
      keystore: resolve(rc().data.root, 'identities', 'keystore'),
      ethKeystore: resolve(rc().data.root, 'identities', 'keystore', 'eth'),
      araKeystore: resolve(rc().data.root, 'identities', 'keystore', 'ara')
    }
  }
})

module.exports = conf => rc(extend(true, defaults(), conf))
