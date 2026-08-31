---
title: Start here
description: Choose the shortest route into Longfellow-ZK for your background and goal.
---

# Start here

Longfellow-ZK provides reusable C++20 proof machinery, plus separate ECDSA,
BIP340, and mdoc circuit packages. Choose the path that matches what you need to
ship.

## Build a project on Longfellow-ZK

1. [Build, test, and install the base library](getting-started.md).
2. Integrate only through an installed `LongfellowZK` CMake target and its
   [documented API and ABI](api.md).
3. Add a [named circuit package](projects/index.md) if your application needs
   ECDSA, BIP340, or mdoc.
4. Before deployment, review the [security and qualification boundary](security.md).

## Maintain a distribution package

1. Follow the [distribution packaging recipe](packaging.md), including staged
   installation, package splitting, and installed-consumer checks.
2. Apply the [0.x ABI policy](abi.md) when naming shared-library packages and
   coordinating transitions.
3. Run the [release qualification](production-qualification.md) appropriate to
   the packaged targets.
4. Ship the GPL license and preserve all file-level upstream notices.

## Evaluate the design

For product context, start with [zero-knowledge in plain language](zero-knowledge.md)
and [use cases](use-cases.md). For technical review, continue to the
[architecture](architecture.md), [specifications](specifications/index.md), and
[interoperability records](interoperability.md).

Longfellow-ZK is not a wallet, credential issuer, blockchain, or blanket
production-safety claim. The circuit, parameters, integration, and release
artifacts must be assessed together.

## Help, support, and licensing

The distribution is licensed under the GNU GPL, version 3 or later. It is free
to use, study, modify, and redistribute; distributed software that uses the
library must be released under the same GPL terms. For adoption, packaging,
security coordination, or licensing needs, contact
[info@dyne.org](mailto:info@dyne.org). We will work with you toward a suitable
solution.
