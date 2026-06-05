# identityd

A purpose-built, multi-model identity database (KV + Document + Graph) built in Zig on LMDB.

## Overview

`identityd` is a storage engine for identity data — users, groups, roles, permissions, and their relationships. It serves as the backend for the SecureMessage/Pacy World IdP and replaces OpenLDAP.

**Architecture:**
- **Engine** — Zig library: document store + graph engine on LMDB
- **identityd** — Daemon: Unix socket + TCP (TLS mandatory), binary wire protocol
- **idctl** — CLI tool: management commands over Unix socket
- **identity-gateway** — (post-MVP) REST/JSON-RPC wrapper

## Building

```sh
zig build
```

## Testing

```sh
zig build test
```

## Status

Phase 0: Storage foundation extracted and tested.

## License

BSD-2-Clause
