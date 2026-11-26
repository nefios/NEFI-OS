# config/

The source of everything NEFI installs on the system.

## Used by the current build

| Folder | Content |
|---|---|
| `includes.chroot/` | Files installed on the system, at the same paths: `includes.chroot/opt/nefi/` becomes `/opt/nefi/`. Contains the Security Center (`usr/lib/nefi/modules/`), the root helpers (`opt/nefi/`), launchers, systemd units and configuration |
| `hooks/normal/0010-…` to `0040-…` | The five setup scripts run once at installation: hardening, tool configuration, Ollama, NEFI setup, branding |

These are packaged into `.deb` files by `packages/nefi-pkgs-gen.sh`.

## Left over from NEFI OS 0.1 (live-build)

Version 0.1 was built with `live-build`. These files are **not used by the current installer build** and are kept for reference:

- `binary`, `bootstrap`, `chroot`, `common`, `source` (live-build settings)
- `bootloaders/`, `package-lists/`, `hooks/live/`
- the hooks in `hooks/normal/` numbered `1000` and above (standard live-build hooks)

Since 0.4 the build no longer depends on them: `packages/nefi-pkgs-gen.sh` finds the files that belong to Debian packages from the Debian archive *Contents* index, not from an old live-build `chroot/` folder. They can be moved to `legacy/` in a future cleanup.

See [Repository layout](https://nefi-os.gitbook.io/docs/project/development/repository-layout).
