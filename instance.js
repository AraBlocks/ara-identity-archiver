const debug = require('debug')('ara:identity:archiver:instance')

/**
 * Instance pointer for this network node.
 * @private
 */
let instance = null

/**
 * Returns the instance pointer.
 * @public
 * @return {Promise<Mixed}
 */
async function getInstance() {
  return instance
}

/**
 * Sets the instance pointer. Will call 'await' on
 * non-null and defined values.
 * @public
 * @param {Mixed}
 */
async function setInstance(value) {
  debug('setting instance=', null === value ? null : typeof value)
  if (null !== value && undefined !== value) {
    instance = await value
  } else {
    instance = null
  }
}

/**
 * Predicate function to return a boolean indicating
 * that module has an instance, or not.
 * @public
 * @return {Boolean}
 */
function hasInstance() {
  return Boolean(null !== instance)
}

module.exports = {
  getInstance,
  hasInstance,
  setInstance
}
