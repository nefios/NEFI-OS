# installer/

Builds the NEFI OS installer ISO: the official Debian 13 installer remastered with `simple-cdd`.

| File | Purpose |
|---|---|
| `build.sh` | **The build command.** Builds the NEFI packages, builds the Debian installer image with simple-cdd and applies the NEFI graphics |
| `nefi.conf` | `simple-cdd` configuration (profile, Debian mirrors) |
| `profiles/nefi.preseed` | Installer answers preset by NEFI (hostname, partitioning, root account, package sources, GRUB…) |
| `profiles/nefi.packages` | Packages installed by default |
| `profiles/nefi.downloads` | Extra packages copied onto the ISO for offline installation |
| `profiles/nefi.postinst` | Commands run at the end of the installation |
| `profiles/nefi.description` | Profile description |
| `nefi-rebrand-iso.sh` | Applies the NEFI graphics and labels to the ISO (boot behavior is unchanged) |

## Usage

```bash
./build.sh                    # version 0.4 by default
NEFI_VERSION=0.4 ./build.sh   # explicit version
```

No Debian DVD is needed: simple-cdd downloads the packages from the Debian mirror and writes an intermediate image, `installer/images/debian-13-amd64-DVD-1.iso`, which the build then rebrands. The final ISO is written to `installer/images/nefi-os-<version>-amd64.iso`.

The build needs **simple-cdd 0.6.10 or later**. Debian 13 ships 0.6.9, which fails: install the two `_all.deb` packages (`python3-simple-cdd` and `simple-cdd`) of version 0.6.10 from the Debian archive.

`images/` and `tmp/` are created by the build and are not stored in Git.

The build downloads the Debian archive *Contents* index from the same mirror (cached in `tmp/contents/`) to find the files that NEFI packages share with Debian packages. If the index cannot be checked, the build stops. `NEFI_SKIP_DEBIAN_CHECK=1` skips the check: use it only for offline test builds, never for a build you publish.

Full guide: [Build from source](https://nefi-os.gitbook.io/docs/project/development/build-from-source).
