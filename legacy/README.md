# legacy/

Files from NEFI OS 0.1, which was built with `live-build`. They are **not used by the current build** and are kept only for reference.

| File | What it was |
|---|---|
| `build.sh` | The 0.1 build script (syntax check, `lb build`, copy of the ISO). Use `installer/build.sh` instead |
| `nefi-os-amd64.packages` | List of the packages installed in the last 0.1 live ISO. It does **not** describe the current release |
| `modules/` | Security Center modules from 0.3 that are no longer loaded in 0.4. See [modules/README.md](modules/README.md) |

The live-build settings still in `config/` are described in [config/README.md](../config/README.md).
