'use strict';

/*
 * Start Stalker only while a specific native function executes.
 *
 * This pattern is the most practical way to stalk the "right" thread
 * without guessing thread ids.
 */

const TARGET_MODULE = 'libc.so';
const TARGET_EXPORT = 'open'; // TODO: change to your target

const cfg = {
  trustThreshold: 1,
  queueCapacity: 16384,
  queueDrainInterval: 0, // manual windows: drain on stop
  excludeModules: [
    'libart.so',
    'libc.so',
    'liblog.so',
    'libdl.so',
  ],
};

const depthByTid = new Map();

function applyConfig() {
  Stalker.trustThreshold = cfg.trustThreshold;
  Stalker.queueCapacity = cfg.queueCapacity;
  Stalker.queueDrainInterval = cfg.queueDrainInterval;
}

function excludeNoise() {
  for (const name of cfg.excludeModules) {
    try {
      const m = Process.getModuleByName(name);
      Stalker.exclude({ base: m.base, size: m.size });
    } catch (_) {
      // ignore
    }
  }
}

function startForCurrentThread() {
  const tid = Process.getCurrentThreadId();
  const depth = (depthByTid.get(tid) || 0) + 1;
  depthByTid.set(tid, depth);

  if (depth !== 1) return tid;

  applyConfig();
  excludeNoise();

  Stalker.follow(tid, {
    events: { call: true, ret: false, exec: false, block: false, compile: false },
    onCallSummary(summary) {
      send({ type: 'stalker:call-summary', tid, summary });
    },
  });

  return tid;
}

function stopForThread(tid) {
  const depth = (depthByTid.get(tid) || 0) - 1;
  if (depth > 0) {
    depthByTid.set(tid, depth);
    return;
  }
  depthByTid.delete(tid);

  Stalker.unfollow(tid);
  Stalker.flush(); // triggers summary window drain
  Stalker.garbageCollect();
}

const target = Process.getModuleByName(TARGET_MODULE).getExportByName(TARGET_EXPORT);
send({ type: 'hook:installed', target: `${TARGET_MODULE}!${TARGET_EXPORT}`, address: target.toString() });

Interceptor.attach(target, {
  onEnter(args) {
    this._stalkerTid = startForCurrentThread();
  },
  onLeave(retval) {
    stopForThread(this._stalkerTid);
  },
});

