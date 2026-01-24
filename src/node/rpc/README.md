# RPC Module Scaffold

The RPC layer will expose both public node APIs and privileged wallet/operational calls.

Focus areas:
- `rpc/server.*` – HTTP/JSON (eventually gRPC) server with TLS and authn hooks.
- `rpc/commands/*` – logically grouped handlers (chain, mempool, wallet, net).
- `rpc/types.*` – shared JSON serialization, error codes, and version negotiation.
- `rpc/policy.*` – command whitelisting (public vs. admin vs. wallet-daemon).

CI will exercise RPC integration tests once the wallet/net subsystems land.

