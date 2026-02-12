# Frida Stalker API Notes (Frida 17+)

Use this as a compact refresher while writing/patching Stalker scripts.

## Follow / Unfollow Lifecycle

- `Stalker.follow([threadId, options])`
- Provide `options.events` to enable specific event kinds.
- Provide exactly one callback:
- `onReceive(events)`: receives a binary blob (one or more GumEvent structs).
- `onCallSummary(summary)`: receives a key-value mapping of call target to call count for the current time window.

- `Stalker.unfollow([threadId])`: stop stalking a thread.
- `Stalker.flush()`: drain buffered events now.
- `Stalker.garbageCollect()`: free accumulated memory at a safe point after `unfollow()`.

Practical stop pattern:

```js
Stalker.unfollow(tid);
Stalker.flush();
Stalker.garbageCollect();
```

## Events

Typical event knobs used in `options.events`:

- `call`: call instructions
- `ret`: return instructions
- `exec`: every instruction (very high volume)
- `block`: basic block executed
- `compile`: basic block compiled (useful for coverage-like workflows)

## Parsing `onReceive` Buffers

`Stalker.parse(events[, options])` parses the buffer.

Useful parse options:

- `annotate: true`: include event type info
- `stringify: true`: pointer values as strings instead of `NativePointer` objects (less overhead if you're sending the result to the host)

Example:

```js
onReceive(events) {
  const decoded = Stalker.parse(events, { annotate: true, stringify: true });
  send({ type: "stalker:events", decoded });
}
```

## Excluding Ranges

`Stalker.exclude(range)` excludes a `{ base, size }` range.

Practical use:

- Exclude system libraries to reduce noise and overhead.
- Excluding means Stalker won't follow execution "inside" that range, but you can still see calls into it and returns back.

Example:

```js
const libc = Process.getModuleByName("libc.so");
Stalker.exclude({ base: libc.base, size: libc.size });
```

## Performance Knobs

- `Stalker.trustThreshold`
- `-1`: no trust (slow)
- `0`: trust code immediately
- `N`: trust after N executions

- `Stalker.queueCapacity`: max queued events (default 16384).
- `Stalker.queueDrainInterval`: ms between periodic drains (default 250).
- Set drain interval to `0` to disable periodic draining and call `Stalker.flush()` manually.

## `transform(iterator)` (Advanced)

If you provide `transform(iterator)`, it is called synchronously when Stalker recompiles a basic block.

Rules of thumb:

- Always call `iterator.keep()` for instructions you want to keep.
- Not calling `keep()` drops the instruction (allows replacement, but can break correctness).
- On ARM/ARM64, be careful with exclusive store sequences.
- A safe gating heuristic is to only emit callouts when `iterator.memoryAccess === "open"`.

## Call Probes

`Stalker.addCallProbe(address, callback[, data])` calls `callback` synchronously when a call is made to `address`.

- Returns an id; remove later with `Stalker.removeCallProbe(id)`.
- For performance, `callback` may be a native function pointer implemented using `CModule`.

