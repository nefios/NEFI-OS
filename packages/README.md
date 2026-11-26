# packages/

NEFI is delivered as Debian packages. This folder contains their generators and the build script.

| File / folder | Purpose |
|---|---|
| `build-debs.sh` | Runs the generators, stamps a new version on each package and builds the `.deb` files into `out/` |
| `nefi-pkgs-gen.sh` | Assembles `nefi-security-center`, `nefi-desktop` and `nefi-ollama` from `config/includes.chroot/` and the setup hooks. Files that also belong to a Debian package are found with the Debian *Contents* index and moved aside with `dpkg-divert` |
| `nefi-tasks-gen.sh` | Generates the installer's *Software selection* entries (`nefi-tasks`) and adds their packages to the ISO |
| `nefi-branding/` | The `nefi-branding` package (`/usr/lib/os-release`), stored as is |
| `nefi-tasks/` | The `nefi-tasks` package, filled in by `nefi-tasks-gen.sh` |

`out/` and the generated `nefi-security-center/`, `nefi-desktop/` and `nefi-ollama/` folders are created by the build and are not stored in Git.

`build-debs.sh` is called by `installer/build.sh`; you rarely need to run it by hand.

> After a build, restore the version stamps the build writes into `*/DEBIAN/control` and never commit them:
>
> ```bash
> git checkout -- $(git diff --name-only | grep DEBIAN/control)
> ```

Details: [Packages](https://nefi-os.gitbook.io/docs/project/development/packages).
