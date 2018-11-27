const { getInstance } = require('./instance')
const { configure } = require('./configure')
const { start } = require('./start')
const { stop } = require('./stop')

module.exports = {
  getInstance,
  configure,
  start,
  stop,
}
