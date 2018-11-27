const { getInstance, setInstance } = require('./instance')
const { warn } = require('ara-console')('identity-archiver')

async function stop() {
  const channel = await getInstance()

  warn('Stopping identity archiver network node.')
  await channel.destroy()
  setInstance(null)

  return true
}

module.exports = {
  stop
}
