# Adapters

The only place `bun:*` imports are allowed (runtime hedge, design §2). Each
adapter wraps one Bun-specific surface (`bun:sqlite`, workers, low-level
sockets) behind a plain interface consumed by `src/core/`.
