'use strict'

const { resolve } = require('path')
const extend = require('extend')
const rc = require('ara-identity-archiver/rc')

const defaults = () => ({
  network: {
    identity: {
      archive: {
        nodes: {
          store: resolve(rc().network.identity.archive.root, 'nodes.json')
        }
      }
    }
  }
})

module.exports = (conf) => rc(extend(true, defaults(), conf))
