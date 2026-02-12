# Frida Stalker (Android) templates

Frida 17+ Stalker templates and workflow for Android (ARM/ARM64): call summaries, event parsing, transforms, module filtering, and safe start/stop patterns.

## What's in here

- `SKILL.md`: metadata + workflow notes (used by skill loaders, but also readable as plain docs)
- `templates/`: ready-to-run Frida scripts
- `references/`: compact notes to keep scripts consistent with Frida 17+ APIs

## Quick start (Frida CLI)

1. Pick the best default template: `templates/stalker-start-stop-around-hook.js`
2. Edit `TARGET_MODULE` + `TARGET_EXPORT` inside the template.
3. Run it:

```sh
frida -U -f com.example.app -l templates/stalker-start-stop-around-hook.js --no-pause
```

That template starts stalking only while your target function runs, using `Process.getCurrentThreadId()` inside the hook so you don’t have to guess thread IDs.

## Tips

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
