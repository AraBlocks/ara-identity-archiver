<img src="https://github.com/AraBlocks/docs/blob/master/ara.png" width="30" height="30" /> ara-identity-archiver
======================================

[![Build Status](https://travis-ci.com/AraBlocks/ara-identity-archiver.svg?token=Ty4yTmKT8aELetQd1xZp&branch=master)](https://travis-ci.com/AraBlocks/ara-identity-archiver)

An ARA network node that archives identities in a network.

## Installation

```sh
$ npm install ara-identity ara-network ara-identity-archiver
```

## Usage

### Prerequisite

* All Ara network nodes require an ARA ID & a shared network key to be generated. Please refer to [ara-network](https://github.com/AraBlocks/ara-network)'s [ANK CLI](https://github.com/AraBlocks/ara-network/blob/master/bin/ara-network-keys) & [ara-identity](https://github.com/AraBlocks/ara-identity)'s [AID CLI](https://github.com/AraBlocks/ara-identity/blob/master/bin/ara-identity)
* To run Ara network nodes through the command line, please refer to [ara-network](https://github.com/AraBlocks/ara-network)'s [ANN CLI](https://github.com/AraBlocks/ara-network/blob/master/bin/ara)


### Runtime Configuration

[rc]: https://github.com/arablocks/ara-runtime-configuration

[Runtime configuration][rc] can be specified by targeting the
`[network.node.identity-archiver]` _INI_ section or the nested _JSON_ object
`{ network: { node: { 'identity-archiver': { ... }}}`. For clarity, we detail the
options below in _INI_ format.

```ini
[network.node.identity.archiver]
;; @TODO
```

### Programmatic

[interface]: https://github.com/AraBlocks/ara-network/blob/master/README.md

The `ara-identity-archiver` module can be used programmatically as it
conforms to the [`ara-network` node interface][interface].

```js
const identityArchiver = require('ara-identity-archiver')
const rc = require('ara-runtime-configuration')
const program = require('yargs')
const { argv } = program

void async function main() {
  try { await identityArchiver.configure(rc.network.node.identity.archiver, program) }
  catch (err) {
    await identityArchiver.configure({
      identity: DID,
      secret: 'shared-secret-string',
      name: 'keyring-name-entry',
      keyring: 'path-to-keyring-secret-file',
    },
    program)
  }
  await identityArchiver.start(argv)
}()
```

### Command Line (ann)

With the `ann` (or `ara`) command line interface, you can
invoke this network node by running the following:

```sh
$ ann -t ara-identity-archiver -i <DID> \
      -s <shared-secret-string> \
      -n <keyring-name-entry> \
      -k <path-to-keyring-secret-file>
```

To see usage help about this network node interface, ensure ara-network is linked:
 ```sh
$ cd ~/ara-identity-archiver && npm link
$ cd ~/ara-network && npm link ara-identity-archiver
```
and run the following:

```sh
$ ann -t ara-identity-archiver --help
```

## See Also

* [ara-identity](https://github.com/AraBlocks/ara-identity)
* [ara-network](https://github.com/arablocks/ara-network)
* [bittorrent-identity-archiver](https://www.npmjs.com/package/bittorrent-identity-archiver)
* [k-rpc](https://github.com/mafintosh/k-rpc)
* [k-rpc-socket](https://github.com/mafintosh/k-rpc-socket)

## License

LGPL-3.0
