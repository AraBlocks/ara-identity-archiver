<img src="https://github.com/AraBlocks/docs/blob/master/ara.png" width="30" height="30" /> ara-network-node-identity-archiver
======================================

[![Build Status](https://travis-ci.com/AraBlocks/ara-network-node-identity-archiver.svg?token=Ty4yTmKT8aELetQd1xZp&branch=master)](https://travis-ci.com/AraBlocks/ara-network-node-identity-archiver)

An ARA network node that archives identities in a network.

## Installation

```sh
$ npm install ara-network ara-network-node-identity-archiver
```

## Usage

### Prerequisite

* All ARA network nodes require an ARA ID & a shared network key to be generated. Please refer to [ara-network's](https://github.com/AraBlocks/ara-network) ANK CLI

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
const identityArchiver = require('ara-network-node-identity-archiver')
const rc = require('ara-runtime-configuration')
const program = require('yargs')
const { argv } = program

void async function main() {
  try { await identityArchiver.configure(rc.network.node.identity-archiver, program) }
  catch (err) {
    await identityArchiver.configure({
      identity: DID,
      secret: shared-secret-string,
      name: keyring-name-entry,
      keyring: path-to-keyring-secret-file
    },
    program)
  }
  await identityArchiver.start(argv)
}()
```

### Command Line (ann)

With the `ann` (or `ara-network-node`) command line interface, you can
invoke this network node by running the following:

```sh
$ ann -t . -i <DID> -s <shared-secret-string> -n <keyring-name-entry> -k <path-to-keyring-secret-file>
```

To see usage help about this network node interface, run the following:

```sh
$ ann -t . --help
```

## See Also

* [ara-network](https://github.com/arablocks/ara-network)
* [bittorrent-identity-archiver](https://www.npmjs.com/package/bittorrent-identity-archiver)
* [k-rpc](https://github.com/mafintosh/k-rpc)
* [k-rpc-socket](https://github.com/mafintosh/k-rpc-socket)

## License

LGPL-3.0
