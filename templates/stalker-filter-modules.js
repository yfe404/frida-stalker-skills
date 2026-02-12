'use strict';

/*
 * Helper functions for identifying app modules on Android.
 *
 * This is deliberately heuristic. Always print and validate on your target.
 */

function isProbablyAppModule(m) {
  const p = String(m.path || '').toLowerCase();
  if (p.includes('/data/app/')) return true;
  if (p.includes('/data/data/')) return true;

  // Some apps load libs from unpacked or relocated locations.
  if (p.includes('/data/')) {
    if (p.includes('/data/dalvik-cache/')) return false;
    return true;
  }

  return false;
}

function getAppModules() {
  return Process.enumerateModules().filter(isProbablyAppModule);
}

function toRange(m) {
  return { base: m.base, size: m.size, name: m.name, path: m.path };
}

function excludeModulesByName(names) {
  for (const name of names) {
    try {
      const m = Process.getModuleByName(name);
      Stalker.exclude({ base: m.base, size: m.size });
    } catch (_) {
      // ignore
    }
  }
}

rpc.exports = {
  getappmodules() {
    return getAppModules().map(toRange);
  },
  excludemodules(names) {
    excludeModulesByName(names || []);
  },
};

