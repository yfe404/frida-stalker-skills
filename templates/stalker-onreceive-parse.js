'use strict';

/*
 * Stalker template using onReceive() + Stalker.parse().
 *
 * Use this when you need ordered events and can afford more overhead.
 */

const defaultConfig = {
  trustThreshold: 1,
  queueCapacity: 16384,
  queueDrainInterval: 250,
  parse: {
    annotate: true,
    stringify: true,
  },
  maxDecodedEvents: 2000,
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

function start(threadId, config) {
  const tid = Number(threadId);
  if (!Number.isFinite(tid)) throw new Error('start(threadId): threadId must be a number');
  if (state.following.has(tid)) return;

  const cfg = { ...state.config, ...(config || {}) };
  applyConfig(cfg);

  Stalker.follow(tid, {
    events: {
      call: true,
      ret: true,
      exec: false,
      block: false,
      compile: false,
    },
    onReceive(events) {
      let decoded;
      try {
        decoded = Stalker.parse(events, cfg.parse);
        if (Array.isArray(decoded) && cfg.maxDecodedEvents > 0 && decoded.length > cfg.maxDecodedEvents) {
          decoded = decoded.slice(0, cfg.maxDecodedEvents);
        }
      } catch (e) {
        send({ type: 'stalker:parse-error', tid, error: String(e) });
        return;
      }

      send({ type: 'stalker:events', tid, decoded });
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

rpc.exports = { start, stop };

send({ type: 'frida-stalker-android:onreceive-ready', frida: Frida.version, arch: Process.arch });

