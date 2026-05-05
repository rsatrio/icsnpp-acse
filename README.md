# ICSNPP-ACSE

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Association Control Service Element (ACSE)

## Overview

This plugin provides a protocol analyzer for Association Control Service
Element (ACSE) (ISO 8650 / X.227) for use within Zeek. The analyzer enables
Zeek to parse ACSE messages.

## Dependencies

As ACSE is an application protocol based on the OSI stack, the underlying ISO
protocol layers must also be processed. The following plugins must therefore
also be installed:

- [TPKT](https://github.com/DINA-community/icsnpp-tpkt)
- [COTP](https://github.com/DINA-community/icsnpp-cotp)
- [SESS](https://github.com/DINA-community/icsnpp-sess)
- [PRES](https://github.com/DINA-community/icsnpp-pres)

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html).

```bash
zkg install https://github.com/DINA-community/icsnpp-acse
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly, users will see `ANALYZER_ACSE` under the list of plugins.

If users have ZKG configured to load packages (see `@load packages` in the [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and these scripts will automatically be loaded and ready to go.

## Logging

One dataset is logged for each AARE pdu containing the following fields. 

| Field             | Type      | Description                                                               |
| ----------------- |-----------|---------------------------------------------------------------------------|
| ts                | time      | Timestamp of the pdu                                                      |
| uid               | string    | Unique ID for this connection                                             |
| orig_h            | address   | Source IP address                                                         |
| orig_p            | port      | Source port                                                               |
| resp_h            | address   | Destination IP address                                                    |
| resp_p            | port      | Destination port                                                          |
| context_name      | string    | context name of the request                                               |
| calling_ap_title  | string    | ap title of the caller                                                    |
| called_ap_title   | string    | responding ap title from aare if available else called ap title from aarq |
| auth_mechanism    | string    | choosen authentication mechanism if any                                   |
| result            | string    | result of the response or the abort pdu                                   |
| aborted           | string    | true if an abort pdu was received                                         |
| diag              | string    | diagnostic data if any                                                    |

## License

The software was developed on behalf of the BSI (Federal Office for Information Security)

Copyright (c) 2025-2026 by DINA-Community BSD 3-Clause. [See License](/COPYING)
