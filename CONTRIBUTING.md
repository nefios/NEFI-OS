# Contributing to NEFI OS

Thank you for your interest in NEFI OS. Bug reports, test results, documentation fixes and pull requests are all welcome.

The full guide is in the documentation: **[Contributing](https://nefi-os.gitbook.io/docs/project/development/contributing)**. This page is the short version.

## Report a bug

Open an [issue](https://github.com/nefios/NEFI-OS/issues/new/choose) and include:

- the NEFI OS version (`cat /etc/os-release`);
- virtual machine (hypervisor and version) or physical hardware;
- what you did, what you expected and what happened;
- relevant logs: `/var/log/nefi-setup/` for installation problems.

## Report a vulnerability

**Do not open a public issue.** Follow [SECURITY.md](SECURITY.md).

## Share test results

NEFI OS has been validated only in virtual machines. Reports from other hypervisors, physical hardware and Secure Boot setups are especially useful: open an issue with the details.

## Send a pull request

1. For anything larger than a small fix, **open an issue first** so the approach can be agreed before you write the code.
2. Fork the repository and create a branch from `main`.
3. Keep the pull request focused on one change.
4. Test it: build the ISO and install it in a virtual machine ([Build from source](https://nefi-os.gitbook.io/docs/project/development/build-from-source)), or at least check that the Python modules compile:

   ```bash
   python3 -m py_compile config/includes.chroot/usr/lib/nefi/modules/*.py
   ```

   and run the unit tests (see [tests/README.md](tests/README.md)):

   ```bash
   for t in tests/test_*.py; do python3 "$t" || break; done
   ```

5. Do not commit the version stamps that the build writes into `packages/*/DEBIAN/control`.
6. Describe what you changed, why, and how you tested it. The pull request template will guide you.

## Rules for code that runs as root

NEFI OS is a security product. Code that needs root follows the [privilege model](https://nefi-os.gitbook.io/docs/user-guide/security/architecture-and-privilege-model):

- the Security Center never runs as root; anything that needs root is a helper in `/opt/nefi/` called through `pkexec`;
- helpers validate their arguments and never pass user input to a shell;
- firewall features use their own nftables table and never flush the base table;
- configuration changes are validated before they are applied (`visudo -c`, `sshd -t`…).

## License

By contributing, you agree that your contributions are released under the [GNU General Public License v3.0](LICENSE), the license of the project.
