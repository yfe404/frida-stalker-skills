# Frida Stalker (Android) agent skill

An installable agent skill for tracing Android native code with Frida Stalker (Frida 17+): call summaries, event parsing, transforms, module filtering, and performance-safe start/stop patterns.

## What's in here

- `SKILL.md`: the skill definition (YAML frontmatter + instructions)
- `templates/`: script templates the agent can adapt
- `references/`: API + Android notes used by the agent while editing templates

## Install (npx skills)

This repo follows the open Agent Skills format and is installable with the `skills` CLI.

List what’s installable from this repo:
```sh
npx skills add yfe404/frida-stalker-skills --list
```

Install globally to Codex (recommended):
```sh
npx skills add yfe404/frida-stalker-skills --skill '*' -g -a codex -y
```

Install into the current project only:
```sh
npx skills add yfe404/frida-stalker-skills --skill '*' -a codex -y
```

Verify installation:
```sh
npx skills list -g -a codex
```

## Troubleshooting install errors

- If you see YAML errors about `description` type, ensure `SKILL.md` frontmatter has a *string* description (quoted), not a YAML list.
