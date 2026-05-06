# pi-sandbox

Standalone pi extension that runs bash commands inside a Linux Bubblewrap (`bwrap`) sandbox and blocks pi file-tool access outside the same path policy.

## Location

Installed as a global auto-discovered extension:

```text
~/.pi/agent/extensions/pi-sandbox/index.ts
```

Reload pi with `/reload` after editing config.

## Requirements

Linux with Bubblewrap installed:

```bash
sudo apt install bubblewrap
# or: sudo dnf install bubblewrap
```

On non-Linux systems the extension loads but sandboxing remains inactive.

## Config files

Merged in order; project config overrides user config:

```text
~/.pi/agent/pi-sandbox.json
<cwd>/.pi/pi-sandbox.json
```

Minimal:

```json
{
  "enabled": true
}
```

Full shape:

```json
{
  "enabled": true,
  "network": "host",
  "paths": {
    ".": { "mode": "write" },
    "/tmp": { "mode": "write" },
    "~/.ssh": { "mode": "deny" },
    "/etc": [
      { "path": "/etc/hosts" },
      {
        "path": "/etc/passwd",
        "content": "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n"
      }
    ]
  },
  "env": {
    "allow": null,
    "deny": ["*_TOKEN", "*_SECRET", "*_PASSWORD", "*_KEY"],
    "set": {
      "NO_COLOR": "1",
      "AWS_PROFILE": null
    }
  }
}
```

## Options

- `enabled`: default `false`.
- `network`: `"host"` default, or `"none"` to add `--unshare-net`.
- `paths`: map of path prefixes to entries. `~`, `$VAR`, and `${VAR}` are expanded.
- path entry `mode`: `"read"` default, `"write"`, or `"deny"`.
- path entry `path`: exact path instead of prefix matching.
- path entry `content`: expose a synthetic read-only file inside sandboxed bash.
- `env.allow`: `null` means inherit all env vars; `[]` means inherit none; globs supported.
- `env.deny`: glob deny list; default strips common secret variables.
- `env.set`: set/override vars; `null` unsets.

## Defaults

- Writable: `.`, `/tmp`, `~/.pi`
- Read-only: `$HOME`, `/usr`, `/opt`, `/srv`, `/etc`, `/nix/store`, `/run/current-system/sw`, `/bin`, `/sbin`, `/lib`, `/lib64`
- Denied/masked: common private and secret paths such as `~/.ssh`, `~/.aws`, `~/.kube`, `~/.docker`, `~/.npmrc`, `~/.anthropic`, etc.

## Commands and flags

- `pi --no-sandbox`: disable for one session.
- `/sandbox`: show active config.

## Notes

This version intentionally omits pi-heimdall's legacy config aliases (`networkAccess`, `writableRoots`, `systemPaths`, `etcReal`, `etcSynthetic`, `envAllowlist`, `extraReadPaths`) and deprecated `stripEnv` helper.
