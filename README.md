# Frida Stalker (Android) skill

Frida 17+ Stalker templates and workflow for Android (ARM/ARM64): call summaries, event parsing, transforms, module filtering, and safe start/stop patterns.

## What's in here

- `SKILL.md`: Codex skill definition and workflow (this is what Codex loads)
- `templates/`: ready-to-run Frida scripts
- `references/`: compact notes to keep scripts consistent with Frida 17+ APIs

## Install as a Codex skill

Option A (symlink):

```sh
ln -s ~/Documents/frida-stalker-android ~/.codex/skills/frida-stalker-android
```

Option B (clone directly into skills dir):

```sh
git clone git@github.com:yfe404/frida-stalker-skills.git ~/.codex/skills/frida-stalker-android
```

## Templates

- `templates/stalker-start-stop-around-hook.js`: start stalking only during a hooked function call (good default)
- `templates/stalker-call-summary.js`: low overhead call counting (`onCallSummary`)
- `templates/stalker-onreceive-parse.js`: ordered events + `Stalker.parse()` decoding
- `templates/stalker-call-probe.js`: observe calls to a single target (`Stalker.addCallProbe`)
- `templates/stalker-transform-skeleton.js`: minimal `transform(iterator)` skeleton (advanced)
- `templates/stalker-filter-modules.js`: helper for app-module filtering on Android

## Notes

- Avoid `events.exec` unless you really need it; it is extremely high volume.
- Prefer `onCallSummary` when ordering is not needed.
- Always `unfollow` + `flush` + `garbageCollect` when repeatedly starting/stopping.

