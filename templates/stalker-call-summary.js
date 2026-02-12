'use strict';

/*
 * Low-overhead Stalker template for Android.
 *
 * What you get: call counts per target, over time windows.
 * What you DON'T get: ordering of calls.
 *
 * Tip: Keep the callback cheap. Symbolication can be done host-side.
 */

const defaultConfig = {
  symbolicate: false,
  trustThreshold: 1,
  queueCapacity: 16384,
  queueDrainInterval: 250,
  excludeModules: [
    'libart.so',
    'libc.so',
    'liblog.so',
    'libdl.so',
  ],
};

const state = {
  following: new Set(),
  config: { ...defaultConfig },
};

function applyConfig(cfg) {
  if (cfg.trustThreshold !== undefined) Stalker.trustThreshold = cfg.trustThreshold;
  if (cfg.queueCapacity !== undefined) Stalker.queueCapacity = cfg.queueCapacity;
  if (cfg.queueDrainInterval !== undefined) Stalker.queueDrainInterval = cfg.queueDrainInterval;
}

function excludeConfiguredModules(cfg) {
  for (const name of (cfg.excludeModules || [])) {
    try {
      const m = Process.getModuleByName(name);
      Stalker.exclude({ base: m.base, size: m.size });
    } catch (_) {
      // Module not present, ignore.
    }
  }
}

function maybeSymbolicateSummary(summary, enabled) {
  if (!enabled) return summary;

  const out = {};
  for (const [target, count] of Object.entries(summary)) {
    try {
      const sym = DebugSymbol.fromAddress(ptr(target)).toString();
      out[sym] = count;
    } catch (_) {
      out[target] = count;
    }
  }
  return out;
}

function start(threadId, config) {
  const tid = Number(threadId);
  if (!Number.isFinite(tid)) throw new Error('start(threadId): threadId must be a number');
  if (state.following.has(tid)) return;

  const cfg = { ...state.config, ...(config || {}) };
  applyConfig(cfg);
  excludeConfiguredModules(cfg);

  Stalker.follow(tid, {
    events: {
      call: true,
      ret: false,
      exec: false,
      block: false,
      compile: false,
    },
    onCallSummary(summary) {
      send({
        type: 'stalker:call-summary',
        tid,
        summary: maybeSymbolicateSummary(summary, cfg.symbolicate),
      });
    },
  });

  state.following.add(tid);
  state.config = cfg;
}

function stop(threadId) {
  const tid = Number(threadId);
  if (!Number.isFinite(tid)) throw new Error('stop(threadId): threadId must be a number');
  if (!state.following.has(tid)) return;

  Stalker.unfollow(tid);
  Stalker.flush();
  Stalker.garbageCollect();

  state.following.delete(tid);
}

function status() {
  return {
    frida: Frida.version,
    arch: Process.arch,
    platform: Process.platform,
    following: Array.from(state.following.values()),
    config: state.config,
  };
}

rpc.exports = {
  start,
  stop,
  status,
};

send({ type: 'frida-stalker-android:ready', ...status() });

