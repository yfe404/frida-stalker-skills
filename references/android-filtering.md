# Android Filtering Notes (Stalker)

Stalker gets unusable quickly if you trace "everything". Filtering is the difference between a usable trace and a dead app.

## Identify "App Code" Modules

Heuristics that often work on Android:

- App native libs typically live under paths containing `/data/app/` or `/data/data/`.
- System libs typically live under `/system/`, `/apex/`, `/vendor/`.

The `templates/stalker-filter-modules.js` template contains a practical `getAppModules()` helper.

## Exclude Noise First

If your goal is "what did my app do", exclude obvious noise modules before you follow:

- `libart.so` (ART runtime)
- `libc.so`
- `liblog.so`
- `libdl.so`

This is not universal; always validate which modules show up in your traces and adjust.

## Start Stalking From The Right Thread

Avoid guessing thread ids.

Better pattern:

- Hook a native function that you know is executed in the thread of interest.
- Inside `onEnter`, call `Process.getCurrentThreadId()` and start stalking that thread.
- Stop stalking in `onLeave` using `unfollow` + `flush` + `garbageCollect`.

See `templates/stalker-start-stop-around-hook.js`.

