'use strict';

/*
 * Call-probe template: observe calls to a specific target address with low overhead.
 *
 * This is useful when you only care about a small set of call targets and do not
 * need full thread stalking.
 */

const TARGET_MODULE = 'libc.so';
const TARGET_EXPORT = 'open'; // TODO: change to your target

const target = Process.getModuleByName(TARGET_MODULE).getExportByName(TARGET_EXPORT);
send({ type: 'call-probe:installed', target: `${TARGET_MODULE}!${TARGET_EXPORT}`, address: target.toString() });

let callCount = 0;
const maxCalls = 5000;

function tryReadArgs(args, n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    try {
      out.push(args[i].toString());
    } catch (_) {
      out.push(null);
    }
  }
  return out;
}

const probeId = Stalker.addCallProbe(target, function (args) {
  callCount++;
  if (callCount > maxCalls) return;

  send({
    type: 'call-probe:hit',
    tid: Process.getCurrentThreadId(),
    address: target.toString(),
    args: tryReadArgs(args, 6),
  });
});

rpc.exports = {
  remove() {
    Stalker.removeCallProbe(probeId);
    send({ type: 'call-probe:removed', probeId });
  },
};

