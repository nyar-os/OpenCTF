# @wae/open-ctf-skills

Agent skill documents for OpenCTF. The package ships
`skills/open-ctf/SKILL.md` and no runtime code.

Use it when an agent should inspect a binary through the `open-ctf` command
line. The skill fixes the preflight checks, the supported routes and the safety
rules for patching.

## Example

```bash
pnpm add @wae/open-ctf-skills
```

Point the agent at `node_modules/@wae/open-ctf-skills/skills/open-ctf/SKILL.md`,
then ask:

> Inspect `samples/app.exe`, list its sections and imports, and show the first
> 20 x64 instructions at the entry point.

The skill must never claim a format, architecture or analysis route that the
installed engine does not expose. Support is defined by
[Capabilities](../../../documentation/capabilities.md); the product overview is
the [root README](../../../readme.md).
