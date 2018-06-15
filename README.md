<img src="https://github.com/AraBlocks/docs/blob/master/ara.png" width="30" height="30" /> ara-network-node-identity-archiver
======================================

[![Build Status](https://travis-ci.com/AraBlocks/ara-network-node-identity-archiver.svg?token=Ty4yTmKT8aELetQd1xZp&branch=master)](https://travis-ci.com/AraBlocks/ara-network-node-identity-archiver)

An ARA network node that archives identities in a network.

## Installation

```sh
$ npm install ara-network ara-network-node-identity-archiver
```

## Usage

### Runtime Configuration

[rc]: https://github.com/arablocks/ara-runtime-configuration

[Runtime configuration][rc] can be specified by targeting the
`[network.node.identity-archiver]` _INI_ section or the nested _JSON_ object
`{ network: { node: { 'identity-archiver': { ... }}}`. For clarity, we detail the
options below in _INI_ format.

```ini
[network.node.identity-archiver]
;; @TODO
```

### Programmatic

[interface]: https://github.com/AraBlocks/ara-network/blob/master/nodes/README.md

The `ara-network-node-identity-archiver` module can be used programmatically as it
conforms to the [`ara-network` node interface][interface].

```js
const { argv } = require('yargs')
const identity-archiver = require('ara-network-node-identity-archiver')
const rc = require('ara-runtime-configuration')

void async function main() {
  try { await identity-archiver.configure(rc.network.node.identity-archiver, require('yargs')) }
  catch (err) { await identity-archiver.configure(null, require('yargs')) }
  await identity-archiver.start(argv)
}()
```

### Command Line (ann)

With the `ann` (or `ara-network-node`) command line interface, you can
invoke this network node by running the following:

```sh
$ ann --type identity-archiver
```

To see usage help about this network node interface, run the following:

```sh
$ ann --type identity-archiver --help
```

## See Also

* [ara-network](https://github.com/arablocks/ara-network)
* [bittorrent-identity-archiver](https://www.npmjs.com/package/bittorrent-identity-archiver)
* [k-rpc](https://github.com/mafintosh/k-rpc)
* [k-rpc-socket](https://github.com/mafintosh/k-rpc-socket)

## License

LGPL-3.0
