'use strict';

/*
 * Minimal transform(iterator) skeleton.
 *
 * Warning: This is advanced and easy to break. Keep it narrow, and filter to
 * app code ranges. Consider doing call summary/onReceive first.
 */

const defaultCfg = {
  trustThreshold: 1,
  queueCapacity: 16384,
  queueDrainInterval: 250,
};

function applyConfig(cfg) {
  Stalker.trustThreshold = cfg.trustThreshold;
  Stalker.queueCapacity = cfg.queueCapacity;
  Stalker.queueDrainInterval = cfg.queueDrainInterval;
}

function start(threadId, appRange) {
  const tid = Number(threadId);
  if (!Number.isFinite(tid)) throw new Error('start(threadId, appRange): bad threadId');
  if (!appRange || !appRange.base || !appRange.size) throw new Error('start(...): appRange must have base/size');

  const appStart = ptr(appRange.base);
  const appEnd = appStart.add(ptr(appRange.size));

  applyConfig(defaultCfg);

  Stalker.follow(tid, {
    transform(iterator) {
      let insn = iterator.next();

      /*
       * On ARM/ARM64, exclusive store sequences are fragile; only emit noisy
       * code/callouts when memory access is "open".
       */
      const canEmitNoisyCode = (iterator.memoryAccess === 'open');

      do {
        const pc = insn.address;
        const isAppCode = pc.compare(appStart) >= 0 && pc.compare(appEnd) < 0;

        if (isAppCode && canEmitNoisyCode) {
          // Example: emit a callout on every "ret" inside app code.
          if (insn.mnemonic === 'ret') {
            iterator.putCallout(onRet);
          }
        }

        iterator.keep();
      } while ((insn = iterator.next()) !== null);
    },
  });
}

function stop(threadId) {
  const tid = Number(threadId);
  if (!Number.isFinite(tid)) throw new Error('stop(threadId): bad threadId');

  Stalker.unfollow(tid);
  Stalker.flush();
  Stalker.garbageCollect();
}

function onRet(context) {
  send({
    type: 'stalker:ret',
    pc: context.pc.toString(),
    sp: context.sp ? context.sp.toString() : undefined,
  });
}

rpc.exports = { start, stop };

